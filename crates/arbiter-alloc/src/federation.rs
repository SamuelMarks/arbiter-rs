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

/// Cryptographically signed cross-cluster resource reservation claim ticket (`ClaimTicket`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimTicket {
    /// Unique ticket identifier.
    pub ticket_id: String,
    /// Issuing home cluster ID.
    pub home_cluster: ClusterId,
    /// Target remote burst peer cluster ID.
    pub target_cluster: ClusterId,
    /// Claimed resource bundle.
    pub claimed_resources: ResourceBundle,
    /// Monotonic tick at which this claim ticket expires if not activated.
    pub expires_at_tick: u64,
    /// Ed25519 public key (32 bytes) of the issuing cluster authority.
    pub issuer_public_key: [u8; 32],
    /// Ed25519 signature (64 bytes) over the canonical claim payload.
    pub signature: Vec<u8>,
}

impl ClaimTicket {
    /// Signs and constructs a new [`ClaimTicket`] using `signing_key_bytes` (32-byte Ed25519 seed).
    ///
    /// # Arguments
    ///
    /// * `ticket_id` - Unique ticket identifier.
    /// * `home_cluster` - Issuing home [`ClusterId`].
    /// * `target_cluster` - Remote burst peer [`ClusterId`].
    /// * `claimed_resources` - Reserved [`ResourceBundle`].
    /// * `expires_at_tick` - Expiration tick.
    /// * `signing_key_bytes` - 32-byte Ed25519 signing key seed.
    ///
    /// # Returns
    ///
    /// Signed [`ClaimTicket`].
    pub fn sign_new(
        ticket_id: &str,
        home_cluster: ClusterId,
        target_cluster: ClusterId,
        claimed_resources: ResourceBundle,
        expires_at_tick: u64,
        signing_key_bytes: &[u8; 32],
    ) -> Self {
        use ed25519_dalek::{Signer, SigningKey};

        let signing_key = SigningKey::from_bytes(signing_key_bytes);
        let issuer_public_key = signing_key.verifying_key().to_bytes();
        let msg = Self::canonical_payload(
            ticket_id,
            &home_cluster,
            &target_cluster,
            &claimed_resources,
            expires_at_tick,
        );
        let sig = signing_key.sign(msg.as_bytes());
        Self {
            ticket_id: ticket_id.to_owned(),
            home_cluster,
            target_cluster,
            claimed_resources,
            expires_at_tick,
            issuer_public_key,
            signature: sig.to_bytes().to_vec(),
        }
    }

    /// Formats the canonical byte string signed by [`Self::sign_new`].
    ///
    /// # Arguments
    ///
    /// * `ticket_id` - Ticket identifier.
    /// * `home_cluster` - Home [`ClusterId`].
    /// * `target_cluster` - Target [`ClusterId`].
    /// * `claimed_resources` - Claimed [`ResourceBundle`].
    /// * `expires_at_tick` - Expiration tick.
    ///
    /// # Returns
    ///
    /// Canonical payload string.
    fn canonical_payload(
        ticket_id: &str,
        home_cluster: &ClusterId,
        target_cluster: &ClusterId,
        claimed_resources: &ResourceBundle,
        expires_at_tick: u64,
    ) -> String {
        format!(
            "{ticket_id}:{home_cluster}:{target_cluster}:{}:{}:{expires_at_tick}",
            claimed_resources.cpu.get(),
            claimed_resources.memory.get()
        )
    }

    /// Verifies the Ed25519 cryptographic signature and TTL validity of this [`ClaimTicket`] at `current_tick`.
    ///
    /// # Arguments
    ///
    /// * `current_tick` - Current monotonic scheduler tick.
    ///
    /// # Returns
    ///
    /// `Ok(())` if the signature is authentic and `current_tick < self.expires_at_tick`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::CryptoSignature`] if the public key or signature is invalid, or
    /// [`ArbiterError::LeaseExpired`] if `current_tick >= self.expires_at_tick`.
    pub fn verify(&self, current_tick: u64) -> ArbiterResult<()> {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        if current_tick >= self.expires_at_tick {
            return Err(ArbiterError::LeaseExpired {
                lease_id: self.ticket_id.clone(),
                expired_at_tick: self.expires_at_tick,
            });
        }
        let verifying_key = VerifyingKey::from_bytes(&self.issuer_public_key)?;
        let sig = Signature::from_slice(&self.signature)?;
        let msg = Self::canonical_payload(
            &self.ticket_id,
            &self.home_cluster,
            &self.target_cluster,
            &self.claimed_resources,
            self.expires_at_tick,
        );
        verifying_key.verify(msg.as_bytes(), &sig)?;
        Ok(())
    }
}

/// Active remote execution lease tracking burst capacity held on a federated peer cluster.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteExecutionLease {
    /// Verified [`ClaimTicket`] backing this remote execution lease.
    pub ticket: ClaimTicket,
    /// Monotonic tick when the remote lease expires if not renewed.
    pub lease_expires_at_tick: u64,
}

/// Reclaims expired or unreachable [`RemoteExecutionLease`]s and credits their `claimed_resources`
/// back to the corresponding peer in `peers`.
///
/// # Arguments
///
/// * `leases` - Mutable vector of active [`RemoteExecutionLease`]s.
/// * `peers` - Mutable slice of [`BurstPeerCandidate`]s.
/// * `current_tick` - Current monotonic scheduler tick.
///
/// # Returns
///
/// Number of reclaimed leases.
pub fn reclaim_expired_or_unreachable_remote_leases(
    leases: &mut Vec<RemoteExecutionLease>,
    peers: &mut [BurstPeerCandidate],
    current_tick: u64,
) -> usize {
    let mut reclaimed_count = 0_usize;
    leases.retain(|lease| {
        let peer_reachable = peers
            .iter()
            .find(|p| p.cluster_id == lease.ticket.target_cluster)
            .is_some_and(|p| p.reachable);
        let expired = current_tick >= lease.lease_expires_at_tick;
        if !peer_reachable || expired {
            for peer in peers.iter_mut() {
                if peer.cluster_id == lease.ticket.target_cluster {
                    peer.idle_capacity = peer
                        .idle_capacity
                        .try_add(&lease.ticket.claimed_resources)
                        .unwrap_or_default();
                }
            }
            reclaimed_count = reclaimed_count.saturating_add(1);
            false
        } else {
            true
        }
    });
    reclaimed_count
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
    #[allow(clippy::too_many_lines)]
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

        // 7. ClaimTicket Ed25519 signature verification & RemoteExecutionLease TTL reclamation
        let seed = [7_u8; 32];
        let home = ClusterId::new("us-east-1").unwrap_or_default();
        let target = ClusterId::new("peer-large").unwrap_or_default();
        let mut claimed = ResourceBundle::zero();
        claimed.cpu = Millicores::new(4_000);
        let ticket = ClaimTicket::sign_new("ticket-01", home, target.clone(), claimed, 500, &seed);
        assert!(ticket.verify(100).is_ok());
        assert!(ticket.verify(500).is_err());

        let mut bad_sig_len = ticket.clone();
        bad_sig_len.signature.truncate(10);
        assert!(bad_sig_len.verify(100).is_err());

        let mut bad_sig_bytes = ticket.clone();
        bad_sig_bytes.signature = vec![0_u8; 64];
        assert!(bad_sig_bytes.verify(100).is_err());

        let mut bad_pubkey = ticket.clone();
        // 0x02 followed by all 0x00 is a non-canonical / invalid Ed25519 compressed Edwards Y point
        bad_pubkey.issuer_public_key = [2_u8; 32];
        assert!(bad_pubkey.verify(100).is_err());

        for p in &mut peers {
            if p.cluster_id == target {
                p.reachable = true;
            }
        }
        let mut leases = vec![
            RemoteExecutionLease {
                ticket: ticket.clone(),
                lease_expires_at_tick: 200,
            },
            RemoteExecutionLease {
                ticket,
                lease_expires_at_tick: 800,
            },
        ];
        assert_eq!(
            reclaim_expired_or_unreachable_remote_leases(&mut leases, &mut peers, 300),
            1
        );
        assert_eq!(leases.len(), 1);
        for p in &mut peers {
            p.reachable = false;
        }
        assert_eq!(
            reclaim_expired_or_unreachable_remote_leases(&mut leases, &mut peers, 350),
            1
        );
        assert!(leases.is_empty());
    }
}
