//! Hierarchical Dominant Resource Fairness (`HDRF`) scheduler calculations.
//!
//! Computes exact fixed-point multi-resource dominant shares across `(CPU, Memory, HugePages,
//! GPU Compute, GPU VRAM, TPU Chips, Disk, Network Bandwidth)` using [`SharePartsPerBillion`].
//! Traverses hierarchical role trees and deterministically orders candidate roles and frameworks.

use std::collections::BTreeMap;

use arbiter_core::error::{ArbiterError, ArbiterResult};
use arbiter_core::ids::{FrameworkId, RoleName};
use arbiter_core::resources::ResourceBundle;
use arbiter_core::units::{SharePartsPerBillion, WeightBasisPoints};
use arbiter_core::workload::RoleHierarchy;
use serde::{Deserialize, Serialize};

/// Dominant resource dimension that determined a role or framework's dominant share.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ResourceDimension {
    /// CPU millicores.
    Cpu,
    /// System RAM bytes.
    Memory,
    /// `HugePage` bytes.
    HugePages,
    /// GPU compute millicores.
    GpuCompute,
    /// GPU VRAM bytes.
    GpuVram,
    /// Discrete TPU chips.
    TpuChips,
    /// Storage disk bytes.
    Disk,
    /// Network bandwidth bits per second.
    NetworkBandwidth,
}

/// Computed dominant share and tie-breaking metadata for a role or framework.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DominantShareEntry {
    /// Role name.
    pub role: RoleName,
    /// Optional framework identifier within the role.
    pub framework_id: Option<FrameworkId>,
    /// Unweighted dominant share in parts per billion (`0..=1_000_000_000`).
    pub raw_dominant_share: SharePartsPerBillion,
    /// Weight-normalized dominant share (`(raw_dominant_share * 10_000) / weight_bps`).
    pub weighted_dominant_share: SharePartsPerBillion,
    /// The resource dimension that yielded `raw_dominant_share`.
    pub dominant_dimension: ResourceDimension,
    /// Number of active allocations held by this entity (used for deterministic tie-breaking).
    pub allocation_count: u64,
}

/// Computes the unweighted dominant resource share of `allocated` relative to `total_capacity`.
///
/// Any resource dimension where `total_capacity` is zero is skipped unless `allocated` is non-zero
/// on that dimension, in which case [`ArbiterError::InsufficientResources`] is returned.
///
/// # Arguments
///
/// * `allocated` - Currently allocated [`ResourceBundle`].
/// * `total_capacity` - Total cluster capacity [`ResourceBundle`].
///
/// # Returns
///
/// Tuple `(SharePartsPerBillion, ResourceDimension)` of the maximum share across all active dimensions.
///
/// # Errors
///
/// Returns [`ArbiterError::InsufficientResources`] if `allocated` has a non-zero quantity on a
/// dimension whose `total_capacity` is zero, or [`ArbiterError::ArithmeticOverflow`] if `allocated`
/// exceeds `total_capacity` by a factor overflowing `u64`.
pub fn compute_dominant_share(
    allocated: &ResourceBundle,
    total_capacity: &ResourceBundle,
) -> ArbiterResult<(SharePartsPerBillion, ResourceDimension)> {
    let dimensions: [(u64, u64, ResourceDimension, &str); 8] = [
        (
            allocated.cpu.get(),
            total_capacity.cpu.get(),
            ResourceDimension::Cpu,
            "cpu",
        ),
        (
            allocated.memory.get(),
            total_capacity.memory.get(),
            ResourceDimension::Memory,
            "memory",
        ),
        (
            allocated.hugepages.get(),
            total_capacity.hugepages.get(),
            ResourceDimension::HugePages,
            "hugepages",
        ),
        (
            allocated.gpu_compute.get(),
            total_capacity.gpu_compute.get(),
            ResourceDimension::GpuCompute,
            "gpu_compute",
        ),
        (
            allocated.gpu_vram.get(),
            total_capacity.gpu_vram.get(),
            ResourceDimension::GpuVram,
            "gpu_vram",
        ),
        (
            allocated.tpu_chips.get(),
            total_capacity.tpu_chips.get(),
            ResourceDimension::TpuChips,
            "tpu_chips",
        ),
        (
            allocated.disk.get(),
            total_capacity.disk.get(),
            ResourceDimension::Disk,
            "disk",
        ),
        (
            allocated.network_bandwidth.get(),
            total_capacity.network_bandwidth.get(),
            ResourceDimension::NetworkBandwidth,
            "network_bandwidth",
        ),
    ];

    let mut max_share = SharePartsPerBillion::ZERO;
    let mut max_dim = ResourceDimension::Cpu;

    for (alloc_val, cap_val, dim, name) in dimensions {
        if cap_val == 0 {
            if alloc_val > 0 {
                return Err(ArbiterError::InsufficientResources {
                    resource: name.to_owned(),
                    requested: alloc_val,
                    available: 0,
                });
            }
            continue;
        }
        let share = SharePartsPerBillion::from_ratio(alloc_val, cap_val)?;
        if share > max_share {
            max_share = share;
            max_dim = dim;
        }
    }

    Ok((max_share, max_dim))
}

/// Accounting state for a single role or framework in the HDRF allocator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleAllocationState {
    /// Role name.
    pub role: RoleName,
    /// Optional framework identifier.
    pub framework_id: Option<FrameworkId>,
    /// Currently allocated resources.
    pub allocated: ResourceBundle,
    /// Number of active tasks/allocations.
    pub allocation_count: u64,
}

/// Evaluates and sorts active roles/frameworks according to Hierarchical Dominant Resource Fairness (`HDRF`).
///
/// Parent role usage is aggregated across all descendant child roles. Candidates are ordered by:
/// 1. Parent role's weighted dominant share (ascending), if a parent exists.
/// 2. Candidate's own weighted dominant share (ascending).
/// 3. Candidate's `allocation_count` (ascending).
/// 4. Lexicographical `RoleName` (ascending).
/// 5. Lexicographical `FrameworkId` (ascending).
///
/// Candidates whose current allocation has already reached or exceeded their role's `hard_max`
/// on any non-zero quota dimension are excluded unless `allocated` is strictly within `hard_max`.
///
/// # Arguments
///
/// * `hierarchy` - Registered [`RoleHierarchy`] defining weights, parents, and quotas.
/// * `states` - Slice of current [`RoleAllocationState`]s for active roles/frameworks.
/// * `total_capacity` - Total cluster [`ResourceBundle`].
///
/// # Returns
///
/// Deterministically sorted vector of [`DominantShareEntry`]s from most-deserving (lowest share) to least-deserving.
///
/// # Errors
///
/// Returns [`ArbiterError::RoleNotFound`] if a state references an unregistered role, or arithmetic
/// errors if capacity is violated.
pub fn rank_hdrf_candidates(
    hierarchy: &RoleHierarchy,
    states: &[RoleAllocationState],
    total_capacity: &ResourceBundle,
) -> ArbiterResult<Vec<DominantShareEntry>> {
    // 1. Validate states, aggregate role totals, and compute per-state raw/weighted shares.
    let mut role_totals: BTreeMap<RoleName, ResourceBundle> = BTreeMap::new();
    for role_def in hierarchy.roles() {
        role_totals.insert(role_def.name.clone(), ResourceBundle::zero());
    }

    let mut state_shares: Vec<(
        &RoleAllocationState,
        Option<RoleName>,
        SharePartsPerBillion,
        SharePartsPerBillion,
        ResourceDimension,
    )> = Vec::with_capacity(states.len());

    for state in states {
        let role_def = hierarchy.get_role(&state.role)?;
        let current = role_totals
            .get(&state.role)
            .cloned()
            .unwrap_or_else(ResourceBundle::zero);
        let updated = current.try_add(&state.allocated)?;
        if !role_def.quota.hard_max.contains(&updated) {
            return Err(ArbiterError::QuotaExceeded {
                role: state.role.to_string(),
                resource: "hard_max".to_owned(),
            });
        }
        role_totals.insert(state.role.clone(), updated);

        // Walk the full ancestor chain (child -> parent -> grandparent -> root), aggregating usage
        // and enforcing every ancestor's hard_max ceiling.
        let mut cursor_parent = role_def.parent.clone();
        while let Some(parent_name) = cursor_parent {
            let parent_curr = role_totals
                .get(&parent_name)
                .cloned()
                .unwrap_or_else(ResourceBundle::zero);
            let parent_updated = parent_curr.try_add(&state.allocated)?;
            let parent_info = hierarchy.roles().iter().find(|r| r.name == parent_name);
            let within_max = parent_info.is_none_or(|p| p.quota.hard_max.contains(&parent_updated));
            if !within_max {
                return Err(ArbiterError::QuotaExceeded {
                    role: parent_name.to_string(),
                    resource: "ancestor_hard_max".to_owned(),
                });
            }
            let next_parent = parent_info.and_then(|p| p.parent.clone());
            role_totals.insert(parent_name, parent_updated);
            cursor_parent = next_parent;
        }

        let (raw_share, dom_dim) = compute_dominant_share(&state.allocated, total_capacity)?;
        let weighted_share = raw_share.saturating_normalize_by_weight(role_def.quota.weight);
        state_shares.push((
            state,
            role_def.parent.clone(),
            raw_share,
            weighted_share,
            dom_dim,
        ));
    }

    // 2. Compute weighted dominant share for each role in the hierarchy.
    let mut role_weighted_shares: BTreeMap<RoleName, SharePartsPerBillion> = BTreeMap::new();
    for role_def in hierarchy.roles() {
        let bundle = role_totals
            .get(&role_def.name)
            .cloned()
            .unwrap_or_else(ResourceBundle::zero);
        let (raw_share, _) = compute_dominant_share(&bundle, total_capacity)?;
        let weighted = raw_share.saturating_normalize_by_weight(role_def.quota.weight);
        role_weighted_shares.insert(role_def.name.clone(), weighted);
    }

    // 3. Build candidate entries with sort keys.
    let mut keyed_entries: Vec<(
        (
            SharePartsPerBillion,
            SharePartsPerBillion,
            u64,
            RoleName,
            Option<FrameworkId>,
        ),
        DominantShareEntry,
    )> = Vec::with_capacity(state_shares.len());

    for (state, parent_opt, raw_share, weighted_share, dom_dim) in state_shares {
        let parent_weighted_share = parent_opt
            .as_ref()
            .and_then(|p| role_weighted_shares.get(p).copied())
            .unwrap_or(weighted_share);

        let entry = DominantShareEntry {
            role: state.role.clone(),
            framework_id: state.framework_id.clone(),
            raw_dominant_share: raw_share,
            weighted_dominant_share: weighted_share,
            dominant_dimension: dom_dim,
            allocation_count: state.allocation_count,
        };

        let sort_key = (
            parent_weighted_share,
            weighted_share,
            state.allocation_count,
            state.role.clone(),
            state.framework_id.clone(),
        );
        keyed_entries.push((sort_key, entry));
    }

    keyed_entries.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(keyed_entries.into_iter().map(|(_, entry)| entry).collect())
}

/// Checks whether a role is currently below its guaranteed minimum quota on any resource dimension.
///
/// # Arguments
///
/// * `allocated` - Currently allocated [`ResourceBundle`] for the role.
/// * `guaranteed_min` - Role's guaranteed minimum [`ResourceBundle`].
///
/// # Returns
///
/// `true` if `allocated` is strictly less than `guaranteed_min` on at least one dimension.
pub fn is_below_guaranteed_quota(
    allocated: &ResourceBundle,
    guaranteed_min: &ResourceBundle,
) -> bool {
    !allocated.contains(guaranteed_min)
}

/// Computes the aggregate unsatisfied `guaranteed_min` quota headroom across all roles in `hierarchy`
/// (Apache Mesos quota headroom parity).
///
/// For each top-level or leaf role with a non-empty `guaranteed_min`, computes the per-dimension
/// shortfall `max(0, guaranteed_min - (allocated + offered))` and sums the shortfalls so non-quota
/// roles cannot starve quota-guaranteed roles of their minimum guarantee.
///
/// # Arguments
///
/// * `hierarchy` - Registered [`RoleHierarchy`].
/// * `states` - Slice of current [`RoleAllocationState`]s.
/// * `outstanding_offers` - Per-role [`ResourceBundle`] of active leased offers.
///
/// # Returns
///
/// Aggregate [`ResourceBundle`] of unsatisfied quota headroom that must be held back for quota roles.
///
/// # Errors
///
/// Returns [`ArbiterError::RoleNotFound`] if a state references an unregistered role, or
/// [`ArbiterError::ArithmeticOverflow`] if headroom summation overflows.
pub fn compute_unsatisfied_quota_headroom(
    hierarchy: &RoleHierarchy,
    states: &[RoleAllocationState],
    outstanding_offers: &BTreeMap<RoleName, ResourceBundle>,
) -> ArbiterResult<ResourceBundle> {
    let mut role_usage: BTreeMap<RoleName, ResourceBundle> = BTreeMap::new();
    for role_def in hierarchy.roles() {
        let offered = outstanding_offers
            .get(&role_def.name)
            .cloned()
            .unwrap_or_else(ResourceBundle::zero);
        role_usage.insert(role_def.name.clone(), offered);
    }
    for state in states {
        let role_def = hierarchy.get_role(&state.role)?;
        let curr = role_usage
            .get(&state.role)
            .cloned()
            .unwrap_or_else(ResourceBundle::zero);
        role_usage.insert(state.role.clone(), curr.try_add(&state.allocated)?);

        let mut cursor_parent = role_def.parent.clone();
        while let Some(parent_name) = cursor_parent {
            let next_parent = hierarchy
                .roles()
                .iter()
                .find(|r| r.name == parent_name)
                .and_then(|r| r.parent.clone());
            let parent_curr = role_usage
                .get(&parent_name)
                .cloned()
                .unwrap_or_else(ResourceBundle::zero);
            role_usage.insert(parent_name, parent_curr.try_add(&state.allocated)?);
            cursor_parent = next_parent;
        }
    }

    let mut total_headroom = ResourceBundle::zero();
    for role_def in hierarchy.roles() {
        let used = role_usage
            .get(&role_def.name)
            .cloned()
            .unwrap_or_else(ResourceBundle::zero);
        let g = &role_def.quota.guaranteed_min;
        let shortfall = ResourceBundle {
            cpu: g.cpu.saturating_sub(used.cpu),
            memory: g.memory.saturating_sub(used.memory),
            hugepages: g.hugepages.saturating_sub(used.hugepages),
            gpu_compute: g.gpu_compute.saturating_sub(used.gpu_compute),
            gpu_vram: g.gpu_vram.saturating_sub(used.gpu_vram),
            tpu_chips: g.tpu_chips.saturating_sub(used.tpu_chips),
            disk: g.disk.saturating_sub(used.disk),
            network_bandwidth: g.network_bandwidth.saturating_sub(used.network_bandwidth),
            ports: arbiter_core::units::PortSet::empty(),
        };
        total_headroom = total_headroom.try_add(&shortfall)?;
    }
    Ok(total_headroom)
}

/// Evaluates and sorts active roles/frameworks according to `HDRF` while accounting for both
/// allocated resources and outstanding leased `ResourceOffer`s (`allocated + offered`).
///
/// # Arguments
///
/// * `hierarchy` - Registered [`RoleHierarchy`].
/// * `states` - Slice of current [`RoleAllocationState`]s.
/// * `outstanding_offers` - Per-role [`ResourceBundle`] of active leased offers.
/// * `total_capacity` - Total cluster [`ResourceBundle`].
///
/// # Returns
///
/// Deterministically sorted vector of [`DominantShareEntry`]s.
///
/// # Errors
///
/// Returns an [`ArbiterError`] if role lookup, quota bounds, or share arithmetic fails.
pub fn rank_hdrf_candidates_with_offers(
    hierarchy: &RoleHierarchy,
    states: &[RoleAllocationState],
    outstanding_offers: &BTreeMap<RoleName, ResourceBundle>,
    total_capacity: &ResourceBundle,
) -> ArbiterResult<Vec<DominantShareEntry>> {
    let mut combined_states = Vec::with_capacity(states.len());
    for state in states {
        let offered = outstanding_offers
            .get(&state.role)
            .cloned()
            .unwrap_or_else(ResourceBundle::zero);
        combined_states.push(RoleAllocationState {
            role: state.role.clone(),
            framework_id: state.framework_id.clone(),
            allocated: state.allocated.try_add(&offered)?,
            allocation_count: state.allocation_count,
        });
    }
    rank_hdrf_candidates(hierarchy, &combined_states, total_capacity)
}

/// Computes the Mesos-style shared persistent volume disk charge (`volume_capacity / max(1, ref_count)`).
///
/// `SharedReadOnly` and `SharedReadWrite` volumes are charged proportionally (`1 / N`) across
/// each sharing task in HDRF calculations.
///
/// # Arguments
///
/// * `volume_capacity` - Total disk [`arbiter_core::units::Bytes`] of the shared persistent volume.
/// * `active_consumer_count` - Number of tasks currently mounting this shared volume (`>= 1`).
///
/// # Returns
///
/// Per-consumer disk [`arbiter_core::units::Bytes`] charge.
pub const fn compute_shared_volume_fair_share(
    volume_capacity: arbiter_core::units::Bytes,
    active_consumer_count: u64,
) -> arbiter_core::units::Bytes {
    let divisor = if active_consumer_count == 0 {
        1
    } else {
        active_consumer_count
    };
    arbiter_core::units::Bytes::new(volume_capacity.get() / divisor)
}

/// Helper to construct a standard [`WeightBasisPoints`] when building test or default role configs.
///
/// # Returns
///
/// [`WeightBasisPoints::STANDARD`].
pub const fn default_role_weight() -> WeightBasisPoints {
    WeightBasisPoints::STANDARD
}

#[cfg(test)]
mod tests {
    use arbiter_core::ids::QuotaId;
    use arbiter_core::units::{BandwidthBps, Bytes, GpuMillicores, Millicores, TpuChips};
    use arbiter_core::workload::{Quota, Role};
    use proptest::prelude::*;

    use super::*;

    fn sample_capacity() -> ResourceBundle {
        ResourceBundle {
            cpu: Millicores::new(100_000),
            memory: Bytes::new(1_000_000_000),
            hugepages: Bytes::new(100_000_000),
            gpu_compute: GpuMillicores::new(8_000),
            gpu_vram: Bytes::new(640_000_000),
            tpu_chips: TpuChips::new(64),
            disk: Bytes::new(10_000_000_000),
            network_bandwidth: BandwidthBps::new(100_000_000_000),
            ..ResourceBundle::zero()
        }
    }

    #[test]
    fn test_compute_dominant_share_dimensions_and_zero_capacity() {
        let cap = sample_capacity();
        let empty = ResourceBundle::zero();
        let (share0, dim0) = compute_dominant_share(&empty, &cap)
            .unwrap_or((SharePartsPerBillion::MAX, ResourceDimension::Disk));
        assert_eq!(share0, SharePartsPerBillion::ZERO);
        assert_eq!(dim0, ResourceDimension::Cpu);

        // GPU dominant (50% GPU vs 10% CPU)
        let mut alloc = ResourceBundle::zero();
        alloc.cpu = Millicores::new(10_000);
        alloc.gpu_compute = GpuMillicores::new(4_000);
        let (share_gpu, dim_gpu) = compute_dominant_share(&alloc, &cap)
            .unwrap_or((SharePartsPerBillion::ZERO, ResourceDimension::Cpu));
        assert_eq!(share_gpu, SharePartsPerBillion::new(500_000_000));
        assert_eq!(dim_gpu, ResourceDimension::GpuCompute);

        // Zero capacity with zero allocation is fine
        let (share_z, _) = compute_dominant_share(&empty, &empty)
            .unwrap_or((SharePartsPerBillion::MAX, ResourceDimension::Cpu));
        assert_eq!(share_z, SharePartsPerBillion::ZERO);

        // Zero capacity with non-zero allocation fails
        assert!(compute_dominant_share(&alloc, &empty).is_err());

        // Huge over-allocation overflowing u64 ratio
        let mut tiny_cap = ResourceBundle::zero();
        tiny_cap.cpu = Millicores::new(1);
        let mut huge_alloc = ResourceBundle::zero();
        huge_alloc.cpu = Millicores::MAX;
        assert!(compute_dominant_share(&huge_alloc, &tiny_cap).is_err());
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_rank_hdrf_candidates_and_tie_breaking() {
        let cap = sample_capacity();
        let mut hierarchy = RoleHierarchy::new();

        let r_prod = RoleName::new("prod").unwrap_or_default();
        let r_prod_ml = RoleName::new("prod.ml").unwrap_or_default();
        let r_batch = RoleName::new("batch").unwrap_or_default();
        let r_unregistered = RoleName::new("unknown").unwrap_or_default();

        let quota_full = Quota {
            id: QuotaId::new("q-1").unwrap_or_default(),
            guaranteed_min: ResourceBundle::zero(),
            hard_max: cap.clone(),
            allow_burst_borrowing: true,
            weight: default_role_weight(),
        };

        assert!(
            hierarchy
                .add_role(Role {
                    name: r_prod.clone(),
                    parent: None,
                    quota: quota_full.clone(),
                })
                .is_ok()
        );
        assert!(
            hierarchy
                .add_role(Role {
                    name: r_prod_ml.clone(),
                    parent: Some(r_prod),
                    quota: quota_full.clone(),
                })
                .is_ok()
        );
        assert!(
            hierarchy
                .add_role(Role {
                    name: r_batch.clone(),
                    parent: None,
                    quota: quota_full,
                })
                .is_ok()
        );

        let mut heavy_alloc = ResourceBundle::zero();
        heavy_alloc.cpu = Millicores::new(50_000); // 50%

        let mut light_alloc = ResourceBundle::zero();
        light_alloc.cpu = Millicores::new(10_000); // 10%

        assert!(is_below_guaranteed_quota(&light_alloc, &heavy_alloc));
        assert!(!is_below_guaranteed_quota(&heavy_alloc, &light_alloc));

        let fw_a = FrameworkId::new("fw-a").unwrap_or_default();
        let fw_b = FrameworkId::new("fw-b").unwrap_or_default();

        let states = vec![
            RoleAllocationState {
                role: r_prod_ml.clone(),
                framework_id: Some(fw_b),
                allocated: heavy_alloc,
                allocation_count: 5,
            },
            RoleAllocationState {
                role: r_batch.clone(),
                framework_id: Some(fw_a),
                allocated: light_alloc,
                allocation_count: 1,
            },
        ];

        let ranked = rank_hdrf_candidates(&hierarchy, &states, &cap).unwrap_or_default();
        assert_eq!(ranked.len(), 2);
        // batch (10% share) must come before prod.ml (50% share)
        assert_eq!(ranked.first().map(|e| &e.role), Some(&r_batch));
        assert_eq!(ranked.get(1).map(|e| &e.role), Some(&r_prod_ml));

        // Unregistered role error
        let bad_states = vec![RoleAllocationState {
            role: r_unregistered,
            framework_id: None,
            allocated: ResourceBundle::zero(),
            allocation_count: 0,
        }];
        assert!(rank_hdrf_candidates(&hierarchy, &bad_states, &cap).is_err());

        // QuotaExceeded when allocated > hard_max
        let mut over_quota = cap.clone();
        over_quota.cpu = Millicores::new(200_000);
        let over_states = vec![RoleAllocationState {
            role: r_batch,
            framework_id: None,
            allocated: over_quota,
            allocation_count: 1,
        }];
        assert!(rank_hdrf_candidates(&hierarchy, &over_states, &cap).is_err());

        // Multi-level ancestor hard_max ceiling enforcement (2 child allocations under r_prod_ml
        // each within hard_max individually if split across two sibling sub-roles, but exceeding parent r_prod hard_max)
        let mut ancestor_hier = RoleHierarchy::new();
        let mut parent_small = cap.clone();
        parent_small.cpu = Millicores::new(30_000);
        let r_root = RoleName::new("dept").unwrap_or_default();
        let r_sub1 = RoleName::new("dept.team1").unwrap_or_default();
        let r_sub2 = RoleName::new("dept.team2").unwrap_or_default();
        let mut child_q = cap;
        child_q.cpu = Millicores::new(15_000);
        let _ = ancestor_hier.add_role(Role {
            name: r_root.clone(),
            parent: None,
            quota: Quota {
                id: QuotaId::new("q-root").unwrap_or_default(),
                guaranteed_min: ResourceBundle::zero(),
                hard_max: parent_small,
                allow_burst_borrowing: true,
                weight: default_role_weight(),
            },
        });
        for sub in [&r_sub1, &r_sub2] {
            let _ = ancestor_hier.add_role(Role {
                name: sub.clone(),
                parent: Some(r_root.clone()),
                quota: Quota {
                    id: QuotaId::new("q-sub").unwrap_or_default(),
                    guaranteed_min: ResourceBundle::zero(),
                    hard_max: child_q.clone(),
                    allow_burst_borrowing: true,
                    weight: default_role_weight(),
                },
            });
        }
        let mut alloc_20k = ResourceBundle::zero();
        alloc_20k.cpu = Millicores::new(15_000);
        let mut alloc_root_20k = ResourceBundle::zero();
        alloc_root_20k.cpu = Millicores::new(20_000);
        let ancestor_exceeded_states = vec![
            RoleAllocationState {
                role: r_root,
                framework_id: None,
                allocated: alloc_root_20k,
                allocation_count: 1,
            },
            RoleAllocationState {
                role: r_sub1,
                framework_id: None,
                allocated: alloc_20k,
                allocation_count: 1,
            },
        ];
        assert!(rank_hdrf_candidates(&ancestor_hier, &ancestor_exceeded_states, &child_q).is_err());
    }

    #[test]
    fn test_rank_hdrf_candidates_overflow_errors() {
        let mut max_cap = ResourceBundle::zero();
        max_cap.cpu = Millicores::MAX;
        let min_weight = WeightBasisPoints::new(1).unwrap_or(WeightBasisPoints::STANDARD);
        let mut max_hier = RoleHierarchy::new();
        let r_p = RoleName::new("p").unwrap_or_default();
        let r_c = RoleName::new("c").unwrap_or_default();
        let q_max = Quota {
            id: QuotaId::new("qm").unwrap_or_default(),
            guaranteed_min: ResourceBundle::zero(),
            hard_max: max_cap.clone(),
            allow_burst_borrowing: true,
            weight: min_weight,
        };
        let _ = max_hier.add_role(Role {
            name: r_p.clone(),
            parent: None,
            quota: q_max.clone(),
        });
        let _ = max_hier.add_role(Role {
            name: r_c.clone(),
            parent: Some(r_p.clone()),
            quota: q_max,
        });

        let mut b_max = ResourceBundle::zero();
        b_max.cpu = Millicores::MAX;
        let overflow_self = vec![
            RoleAllocationState {
                role: r_p.clone(),
                framework_id: None,
                allocated: b_max.clone(),
                allocation_count: 1,
            },
            RoleAllocationState {
                role: r_p.clone(),
                framework_id: None,
                allocated: b_max.clone(),
                allocation_count: 1,
            },
        ];
        assert!(rank_hdrf_candidates(&max_hier, &overflow_self, &max_cap).is_err());

        let overflow_parent = vec![
            RoleAllocationState {
                role: r_p.clone(),
                framework_id: None,
                allocated: b_max.clone(),
                allocation_count: 1,
            },
            RoleAllocationState {
                role: r_c.clone(),
                framework_id: None,
                allocated: b_max,
                allocation_count: 1,
            },
        ];
        assert!(rank_hdrf_candidates(&max_hier, &overflow_parent, &max_cap).is_err());

        let mut one_cpu = ResourceBundle::zero();
        one_cpu.cpu = Millicores::new(1);
        let zero_cap_states = vec![RoleAllocationState {
            role: r_c,
            framework_id: None,
            allocated: one_cpu.clone(),
            allocation_count: 1,
        }];
        assert!(
            rank_hdrf_candidates(&max_hier, &zero_cap_states, &ResourceBundle::zero()).is_err()
        );

        // Step 2 compute_dominant_share overflow: each state has 10_000_000_000 cpu (so 10^19ppb fits in u64),
        // but two states summed = 20_000_000_000 cpu, and 20_000_000_000 * 10^9 / 1 overflows u64::MAX (~1.84 * 10^19)!
        let mut half_ratio_overflow = ResourceBundle::zero();
        half_ratio_overflow.cpu = Millicores::new(10_000_000_000);
        let step2_overflow = vec![
            RoleAllocationState {
                role: r_p.clone(),
                framework_id: None,
                allocated: half_ratio_overflow.clone(),
                allocation_count: 1,
            },
            RoleAllocationState {
                role: r_p,
                framework_id: None,
                allocated: half_ratio_overflow,
                allocation_count: 1,
            },
        ];
        assert!(rank_hdrf_candidates(&max_hier, &step2_overflow, &one_cpu).is_err());
    }

    #[test]
    fn test_quota_headroom_offers_and_shared_volume_share() {
        let mut max_cap = ResourceBundle::zero();
        max_cap.cpu = Millicores::MAX;
        let mut h_headroom = RoleHierarchy::new();
        let r_root = RoleName::new("dept").unwrap_or_default();
        let r_leaf = RoleName::new("dept.ml").unwrap_or_default();
        let mut g_root = ResourceBundle::zero();
        g_root.cpu = Millicores::new(20_000);
        let mut g_leaf = ResourceBundle::zero();
        g_leaf.cpu = Millicores::new(10_000);
        for (r_name, parent_opt, q_name, g_min) in [
            (r_root.clone(), None, "q-r", g_root),
            (r_leaf.clone(), Some(r_root.clone()), "q-l", g_leaf),
        ] {
            let _ = h_headroom.add_role(Role {
                name: r_name,
                parent: parent_opt,
                quota: Quota {
                    id: QuotaId::new(q_name).unwrap_or_default(),
                    guaranteed_min: g_min,
                    hard_max: max_cap.clone(),
                    allow_burst_borrowing: true,
                    weight: WeightBasisPoints::STANDARD,
                },
            });
        }
        let mut alloc_leaf = ResourceBundle::zero();
        alloc_leaf.cpu = Millicores::new(4_000);
        let mut offered_map = BTreeMap::new();
        let mut off_leaf = ResourceBundle::zero();
        off_leaf.cpu = Millicores::new(2_000);
        offered_map.insert(r_leaf.clone(), off_leaf);
        let st_headroom = vec![RoleAllocationState {
            role: r_leaf.clone(),
            framework_id: None,
            allocated: alloc_leaf,
            allocation_count: 1,
        }];
        let headroom = compute_unsatisfied_quota_headroom(&h_headroom, &st_headroom, &offered_map)
            .unwrap_or_default();
        assert_eq!(headroom.cpu, Millicores::new(20_000));

        let bad_st = vec![RoleAllocationState {
            role: RoleName::new("unknown").unwrap_or_default(),
            framework_id: None,
            allocated: ResourceBundle::zero(),
            allocation_count: 0,
        }];
        assert!(compute_unsatisfied_quota_headroom(&h_headroom, &bad_st, &offered_map).is_err());

        let mut max_offered = BTreeMap::new();
        let mut max_b = ResourceBundle::zero();
        max_b.cpu = Millicores::MAX;
        max_offered.insert(r_leaf, max_b.clone());
        assert!(
            compute_unsatisfied_quota_headroom(&h_headroom, &st_headroom, &max_offered).is_err()
        );
        let mut parent_max_offered = BTreeMap::new();
        parent_max_offered.insert(r_root.clone(), max_b.clone());
        assert!(
            compute_unsatisfied_quota_headroom(&h_headroom, &st_headroom, &parent_max_offered)
                .is_err()
        );
        let mut h_shortfall_overflow = RoleHierarchy::new();
        for (r_name, q_name) in [
            (r_root, "q1"),
            (RoleName::new("dept2").unwrap_or_default(), "q2"),
        ] {
            let _ = h_shortfall_overflow.add_role(Role {
                name: r_name,
                parent: None,
                quota: Quota {
                    id: QuotaId::new(q_name).unwrap_or_default(),
                    guaranteed_min: max_b.clone(),
                    hard_max: max_cap.clone(),
                    allow_burst_borrowing: true,
                    weight: WeightBasisPoints::STANDARD,
                },
            });
        }
        assert!(
            compute_unsatisfied_quota_headroom(&h_shortfall_overflow, &[], &BTreeMap::new())
                .is_err()
        );

        let ranked_with_offers =
            rank_hdrf_candidates_with_offers(&h_headroom, &st_headroom, &offered_map, &max_cap)
                .unwrap_or_default();
        assert_eq!(ranked_with_offers.len(), 1);
        assert!(
            rank_hdrf_candidates_with_offers(&h_headroom, &st_headroom, &max_offered, &max_cap)
                .is_err()
        );

        for (cnt, expected) in [(0_u64, 1_000_u64), (4_u64, 250_u64)] {
            assert_eq!(
                compute_shared_volume_fair_share(Bytes::new(1_000), cnt),
                Bytes::new(expected)
            );
        }
    }

    proptest! {
        #[test]
        fn prop_hdrf_prefers_smaller_share(
            cpu_small in 1_000..=20_000_u64,
            cpu_large in 25_000..=80_000_u64,
        ) {
            let cap = sample_capacity();
            let mut hierarchy = RoleHierarchy::new();
            let r_a = RoleName::new("role-a").unwrap_or_default();
            let r_b = RoleName::new("role-b").unwrap_or_default();
            let q = Quota {
                id: QuotaId::new("q").unwrap_or_default(),
                guaranteed_min: ResourceBundle::zero(),
                hard_max: cap.clone(),
                allow_burst_borrowing: true,
                weight: WeightBasisPoints::STANDARD,
            };
            let _ = hierarchy.add_role(Role { name: r_a.clone(), parent: None, quota: q.clone() });
            let _ = hierarchy.add_role(Role { name: r_b.clone(), parent: None, quota: q });

            let mut b_small = ResourceBundle::zero();
            b_small.cpu = Millicores::new(cpu_small);
            let mut b_large = ResourceBundle::zero();
            b_large.cpu = Millicores::new(cpu_large);

            let states = vec![
                RoleAllocationState {
                    role: r_b,
                    framework_id: None,
                    allocated: b_large,
                    allocation_count: 1,
                },
                RoleAllocationState {
                    role: r_a.clone(),
                    framework_id: None,
                    allocated: b_small,
                    allocation_count: 1,
                },
            ];
            let ranked = rank_hdrf_candidates(&hierarchy, &states, &cap).unwrap_or_default();
            prop_assert_eq!(ranked.first().map(|e| &e.role), Some(&r_a));
        }
    }
}
