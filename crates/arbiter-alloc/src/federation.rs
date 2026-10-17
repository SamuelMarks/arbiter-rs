//! Cross-cluster federation workload bursting and offer forwarding (`arbiter-alloc::federation`).
//!
//! Forwards unmet [`TaskSpec`] or atomic [`TaskGroupSpec`] workloads to healthy federated peer
//! clusters (`ClusterId`) that advertise sufficient excess capacity.

use arbiter_core::error::{ArbiterError, ArbiterResult};
use arbiter_core::ids::ClusterId;
use arbiter_core::resources::ResourceBundle;
use arbiter_core::workload::{TaskGroupSpec, TaskSpec};
use serde::{Deserialize, Serialize};

/// Summary of a remote federated cluster peer's bursting eligibility.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BurstPeerCandidate {
    /// Remote cluster identifier.
    pub cluster_id: ClusterId,
    /// Whether the remote cluster control plane is reachable.
    pub reachable: bool,
    /// Advertised idle resource capacity available for overflow bursting.
    pub idle_capacity: ResourceBundle,
}

/// Decision produced when forwarding an unmet workload to a federated peer cluster.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederatedBurstDecision {
    /// Selected target peer cluster ID.
    pub target_cluster: ClusterId,
    /// Total resource bundle reserved against the peer's advertised idle capacity.
    pub consumed_resources: ResourceBundle,
}

/// Selects a healthy federated peer cluster capable of absorbing an unplaced direct [`TaskSpec`].
///
/// # Arguments
///
/// * `task` - Unplaced [`TaskSpec`].
/// * `peers` - Mutable slice of [`BurstPeerCandidate`]s.
///
/// # Returns
///
/// [`FederatedBurstDecision`] naming the target [`ClusterId`].
///
/// # Errors
///
/// Returns [`ArbiterError::FederationPeerUnreachable`] if no reachable peers exist, or
/// [`ArbiterError::NoEligibleAgents`] if no reachable peer has sufficient idle capacity.
pub fn burst_task_to_federation(
    task: &TaskSpec,
    peers: &mut [BurstPeerCandidate],
) -> ArbiterResult<FederatedBurstDecision> {
    if !peers.iter().any(|p| p.reachable) {
        return Err(ArbiterError::FederationPeerUnreachable {
            peer_cluster: "all-peers".to_owned(),
            reason: "no reachable federated peer clusters available for bursting".to_owned(),
        });
    }

    for peer in peers.iter_mut() {
        if !peer.reachable {
            continue;
        }
        if peer.idle_capacity.contains(&task.resources) {
            peer.idle_capacity = peer
                .idle_capacity
                .try_sub(&task.resources)
                .unwrap_or_default();
            return Ok(FederatedBurstDecision {
                target_cluster: peer.cluster_id.clone(),
                consumed_resources: task.resources.clone(),
            });
        }
    }

    Err(ArbiterError::NoEligibleAgents {
        workload: task.task_id.to_string(),
        reason: "no federated peer cluster has sufficient idle capacity for task".to_owned(),
    })
}

/// Selects a healthy federated peer cluster capable of absorbing an entire atomic [`TaskGroupSpec`].
///
/// # Arguments
///
/// * `group` - Unplaced [`TaskGroupSpec`].
/// * `peers` - Mutable slice of [`BurstPeerCandidate`]s.
///
/// # Returns
///
/// [`FederatedBurstDecision`] naming the target [`ClusterId`].
///
/// # Errors
///
/// Returns [`ArbiterError::FederationPeerUnreachable`] if no reachable peers exist, or
/// [`ArbiterError::GangConstraintUnsatisfied`] if no single peer can fit the sum of all gang tasks.
pub fn burst_gang_to_federation(
    group: &TaskGroupSpec,
    peers: &mut [BurstPeerCandidate],
) -> ArbiterResult<FederatedBurstDecision> {
    if !peers.iter().any(|p| p.reachable) {
        return Err(ArbiterError::FederationPeerUnreachable {
            peer_cluster: "all-peers".to_owned(),
            reason: "no reachable federated peer clusters available for gang bursting".to_owned(),
        });
    }

    let mut total_group_req = ResourceBundle::zero();
    for task in &group.tasks {
        total_group_req = total_group_req.try_add(&task.resources)?;
    }

    for peer in peers.iter_mut() {
        if !peer.reachable {
            continue;
        }
        if peer.idle_capacity.contains(&total_group_req) {
            peer.idle_capacity = peer
                .idle_capacity
                .try_sub(&total_group_req)
                .unwrap_or_default();
            return Ok(FederatedBurstDecision {
                target_cluster: peer.cluster_id.clone(),
                consumed_resources: total_group_req,
            });
        }
    }

    Err(ArbiterError::GangConstraintUnsatisfied {
        group_id: group.group_id.to_string(),
        placed: 0,
        required: group.tasks.len(),
    })
}

#[cfg(test)]
mod tests {
    use arbiter_core::ids::{RoleName, TaskGroupId, TaskId};
    use arbiter_core::units::{Bytes, Millicores};
    use arbiter_core::workload::{IsolationSpec, PreemptionPolicy, PriorityClass};

    use super::*;

    fn make_task(id: &str, cpu_m: u64) -> TaskSpec {
        TaskSpec {
            task_id: TaskId::new(id).unwrap_or_default(),
            role: RoleName::new("spot").unwrap_or_default(),
            framework_id: None,
            election_group: None,
            priority: PriorityClass::SpotPreemptible,
            preemption_policy: PreemptionPolicy::GracefulSigterm,
            resources: ResourceBundle {
                cpu: Millicores::new(cpu_m),
                memory: Bytes::new(1024),
                ..ResourceBundle::zero()
            },
            required_gpu_vendor: None,
            required_gpu_partition: None,
            topology_constraints: Vec::new(),
            isolation: IsolationSpec {
                capabilities: Vec::new(),
                image_ref: None,
                command: "/bin/burst".to_owned(),
                args: Vec::new(),
                env: Vec::new(),
                run_as_user: None,
            },
            artifacts: Vec::new(),
            secrets: Vec::new(),
            health_check: None,
        }
    }

    #[test]
    fn test_cross_cluster_task_and_gang_bursting() {
        let mut peers = vec![
            BurstPeerCandidate {
                cluster_id: ClusterId::new("peer-down").unwrap_or_default(),
                reachable: false,
                idle_capacity: ResourceBundle {
                    cpu: Millicores::new(100_000),
                    memory: Bytes::new(100_000),
                    ..ResourceBundle::zero()
                },
            },
            BurstPeerCandidate {
                cluster_id: ClusterId::new("peer-small").unwrap_or_default(),
                reachable: true,
                idle_capacity: ResourceBundle {
                    cpu: Millicores::new(4_000),
                    memory: Bytes::new(10_000),
                    ..ResourceBundle::zero()
                },
            },
            BurstPeerCandidate {
                cluster_id: ClusterId::new("peer-large").unwrap_or_default(),
                reachable: true,
                idle_capacity: ResourceBundle {
                    cpu: Millicores::new(32_000),
                    memory: Bytes::new(100_000),
                    ..ResourceBundle::zero()
                },
            },
        ];

        // 1. Burst direct task needing 8_000m -> skips peer-down and peer-small, lands on peer-large
        let t1 = make_task("burst-t1", 8_000);
        let dec1 = burst_task_to_federation(&t1, &mut peers);
        assert_eq!(
            dec1.map(|d| d.target_cluster),
            Ok(ClusterId::new("peer-large").unwrap_or_default())
        );

        // 2. Direct task needing 64_000m -> NoEligibleAgents
        let t_huge = make_task("burst-huge", 64_000);
        assert!(burst_task_to_federation(&t_huge, &mut peers).is_err());

        // 3. Burst gang needing 2 x 8_000m = 16_000m -> lands on peer-large (which has 24_000m left)
        let gang_ok = TaskGroupSpec {
            group_id: TaskGroupId::new("gang-burst-1").unwrap_or_default(),
            role: RoleName::new("spot").unwrap_or_default(),
            tasks: vec![make_task("g1", 8_000), make_task("g2", 8_000)],
            tpu_slice: None,
            placement_timeout_ms: 500,
        };
        assert!(burst_gang_to_federation(&gang_ok, &mut peers).is_ok());

        // 4. Repeating gang_ok now fails (only 8_000m left on peer-large)
        assert!(burst_gang_to_federation(&gang_ok, &mut peers).is_err());

        // 5. Overflow in gang task sum
        let gang_overflow = TaskGroupSpec {
            group_id: TaskGroupId::new("gang-ovf").unwrap_or_default(),
            role: RoleName::new("spot").unwrap_or_default(),
            tasks: vec![make_task("g1", u64::MAX), make_task("g2", 10)],
            tpu_slice: None,
            placement_timeout_ms: 500,
        };
        assert!(burst_gang_to_federation(&gang_overflow, &mut peers).is_err());

        // 6. All peers unreachable -> FederationPeerUnreachable
        for p in &mut peers {
            p.reachable = false;
        }
        assert!(burst_task_to_federation(&t1, &mut peers).is_err());
        assert!(burst_gang_to_federation(&gang_ok, &mut peers).is_err());
    }
}
