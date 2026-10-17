//! Shared Election, Lease & Fencing Plane ("Consensus-as-a-Service" / `CaaS`) (`arbiter-store::election`).
//!
//! Implements:
//! - **Single-Wire Multiplexed Heartbeat & Lease Renewal**: Co-located stateful workloads
//!   (Postgres, `MySQL`, etcd, Redis, Kafka) piggyback onto the hosting Agent's single Master
//!   lease stream, eliminating $O(N^2)$ application-level gossip storms.
//! - **Workload Election Groups & Monotonic Fencing Tokens (`ElectionGroup`, `LeaseGrant`)**:
//!   Issues time-bounded primary leases carrying strictly monotonic [`FencingToken`]s.
//! - **Deterministic Hardware & OS STONITH Fencing Prerequisite**: Guarantees split-brain immunity
//!   by requiring either deterministic lease TTL expiration OR synchronous OS isolator STONITH
//!   fencing confirmation (process kill + storage unmount + network fabric drop) on the old
//!   primary's Agent before issuing `FencingToken = T + 1` to a standby task.

use std::collections::BTreeMap;

use arbiter_core::error::{ArbiterError, ArbiterResult};
use arbiter_core::ids::{AgentId, ElectionGroupId, FencingToken, LeaseId, TaskId};
use serde::{Deserialize, Serialize};

use crate::traits::StateStore;

/// Hardware and OS STONITH fencing actions executed by an Agent's isolator before standby promotion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StonithFenceReceipt {
    /// Target Agent that executed the fence.
    pub fenced_agent_id: AgentId,
    /// Target primary task that was terminated and fenced.
    pub fenced_task_id: TaskId,
    /// The fencing token epoch that was revoked.
    pub revoked_token: FencingToken,
    /// Whether process/cgroup/`JobObject`/Jail/Zone termination succeeded (`SIGKILL`/`TerminateJobObject`/`jail_remove`).
    pub process_terminated: bool,
    /// Whether storage I/O fencing succeeded (ZFS forced unmount / CSI volume detach).
    pub storage_unmounted: bool,
    /// Whether network fabric fencing succeeded (Crossbow VNIC drop / `VNET` teardown / eBPF drop / HNS block).
    pub network_isolated: bool,
}

impl StonithFenceReceipt {
    /// Validates that all three STONITH isolation layers (process, storage, network) completed cleanly.
    ///
    /// # Returns
    ///
    /// `Ok(())` if all three layers are `true`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::FenceExecutionFailed`] if any isolation layer failed to fence.
    pub fn verify_complete(&self) -> ArbiterResult<()> {
        if !self.process_terminated || !self.storage_unmounted || !self.network_isolated {
            return Err(ArbiterError::FenceExecutionFailed {
                target: format!("{}/{}", self.fenced_agent_id, self.fenced_task_id),
                reason: format!(
                    "incomplete STONITH fence (process={}, storage={}, network={})",
                    self.process_terminated, self.storage_unmounted, self.network_isolated
                ),
            });
        }
        Ok(())
    }
}

/// Time-bounded primary lease grant issued to the elected primary task of an [`ElectionGroup`].
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseGrant {
    /// Unique lease identifier.
    pub lease_id: LeaseId,
    /// Election group this lease governs.
    pub group_id: ElectionGroupId,
    /// Elected primary task identifier.
    pub primary_task_id: TaskId,
    /// Agent hosting the elected primary task.
    pub hosting_agent_id: AgentId,
    /// Strictly monotonic 64-bit fencing token assigned to this primary election.
    pub fencing_token: FencingToken,
    /// Monotonic tick at which this lease expires unless renewed by the Agent's single-wire heartbeat.
    pub expires_at_tick: u64,
}

impl LeaseGrant {
    /// Checks whether this lease is currently active at `current_tick`.
    ///
    /// # Arguments
    ///
    /// * `current_tick` - Monotonic tick.
    ///
    /// # Returns
    ///
    /// `true` if `current_tick < self.expires_at_tick`.
    pub const fn is_active(&self, current_tick: u64) -> bool {
        current_tick < self.expires_at_tick
    }
}

/// Stateful workload election group tracked by the control plane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElectionGroup {
    /// Unique election group identifier (e.g., `"pg-cluster-prod"`).
    pub group_id: ElectionGroupId,
    /// Registered member `(TaskId, AgentId)` candidates in this group.
    pub members: Vec<(TaskId, AgentId)>,
    /// Currently active or most recently issued [`LeaseGrant`].
    pub current_lease: Option<LeaseGrant>,
    /// Lease TTL duration in ticks.
    pub lease_ttl_ticks: u64,
}

/// Multiplexed single-wire heartbeat payload sent from an Agent to the Master.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultiplexedAgentHeartbeat {
    /// Agent sending the heartbeat.
    pub agent_id: AgentId,
    /// Healthy task IDs running on this Agent that wish to renew their co-located election leases.
    pub healthy_tasks: Vec<TaskId>,
    /// Monotonic tick when the heartbeat was processed.
    pub heartbeat_tick: u64,
}

/// Control-plane coordinator for shared `CaaS` workload elections, single-wire lease renewals,
/// and STONITH-verified standby failover.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElectionPlane {
    /// Registered election groups keyed by [`ElectionGroupId`].
    groups: BTreeMap<ElectionGroupId, ElectionGroup>,
    /// Monotonic counter for generating [`LeaseId`]s.
    next_lease_seq: u64,
}

impl ElectionPlane {
    /// Creates an empty [`ElectionPlane`].
    ///
    /// # Returns
    ///
    /// Empty [`ElectionPlane`].
    pub const fn new() -> Self {
        Self {
            groups: BTreeMap::new(),
            next_lease_seq: 1,
        }
    }

    /// Registers a new stateful [`ElectionGroup`].
    ///
    /// # Arguments
    ///
    /// * `group_id` - Unique election group ID.
    /// * `members` - Member `(TaskId, AgentId)` pairs (must be non-empty).
    /// * `lease_ttl_ticks` - Lease TTL in ticks (must be `>= 1`).
    ///
    /// # Returns
    ///
    /// `Ok(())` on registration.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::InvalidResourceQuantity`] if `members` is empty or `lease_ttl_ticks == 0`.
    pub fn register_group(
        &mut self,
        group_id: ElectionGroupId,
        members: Vec<(TaskId, AgentId)>,
        lease_ttl_ticks: u64,
    ) -> ArbiterResult<()> {
        if members.is_empty() || lease_ttl_ticks == 0 {
            return Err(ArbiterError::InvalidResourceQuantity {
                resource: "ElectionGroup".to_owned(),
                quantity: 0,
                reason: "election group must have >= 1 member and lease_ttl_ticks >= 1".to_owned(),
            });
        }
        self.groups.insert(
            group_id.clone(),
            ElectionGroup {
                group_id,
                members,
                current_lease: None,
                lease_ttl_ticks,
            },
        );
        Ok(())
    }

    /// Elects or promotes `candidate_task` as the primary for `group_id`, issuing a new [`LeaseGrant`]
    /// with a strictly monotonic [`FencingToken`] from `store`.
    ///
    /// Split-brain immunity rule:
    /// If a previous [`LeaseGrant`] exists and has NOT yet expired at `current_tick`, promotion is
    /// rejected with [`ArbiterError::SplitBrainDetected`] unless a valid [`StonithFenceReceipt`]
    /// proving synchronous isolator fencing of the old primary is provided.
    ///
    /// # Arguments
    ///
    /// * `store` - Backing [`StateStore`] issuing the monotonic [`FencingToken`].
    /// * `group_id` - Target [`ElectionGroupId`].
    /// * `candidate_task` - Standby or initial [`TaskId`] to promote.
    /// * `current_tick` - Current monotonic tick.
    /// * `stonith_receipt` - Optional [`StonithFenceReceipt`] if promoting before old lease TTL expiration.
    ///
    /// # Returns
    ///
    /// Newly granted [`LeaseGrant`].
    ///
    /// # Errors
    ///
    /// Returns:
    /// - [`ArbiterError::StoreReadError`] if `group_id` or `candidate_task` is not registered.
    /// - [`ArbiterError::SplitBrainDetected`] if the previous primary's lease is still active and no valid STONITH receipt is provided.
    /// - [`ArbiterError::FenceExecutionFailed`] if the provided STONITH receipt is incomplete.
    pub fn elect_or_promote_primary<S: StateStore>(
        &mut self,
        store: &mut S,
        group_id: &ElectionGroupId,
        candidate_task: &TaskId,
        current_tick: u64,
        stonith_receipt: Option<&StonithFenceReceipt>,
    ) -> ArbiterResult<LeaseGrant> {
        let Some(group) = self.groups.get_mut(group_id) else {
            return Err(ArbiterError::StoreReadError {
                key: group_id.to_string(),
                reason: "election group not registered".to_owned(),
            });
        };

        let Some((_, hosting_agent)) = group
            .members
            .iter()
            .find(|(tid, _)| tid == candidate_task)
            .cloned()
        else {
            return Err(ArbiterError::StoreReadError {
                key: candidate_task.to_string(),
                reason: "candidate task is not a member of the election group".to_owned(),
            });
        };

        if let Some(ref prev_lease) = group.current_lease {
            if prev_lease.is_active(current_tick) {
                let Some(receipt) = stonith_receipt else {
                    return Err(ArbiterError::SplitBrainDetected {
                        group_id: group_id.to_string(),
                        details: format!(
                            "cannot promote '{}' while primary '{}' holds active lease until tick {}",
                            candidate_task, prev_lease.primary_task_id, prev_lease.expires_at_tick
                        ),
                    });
                };
                receipt.verify_complete()?;
                if receipt.fenced_task_id != prev_lease.primary_task_id
                    || receipt.revoked_token != prev_lease.fencing_token
                {
                    return Err(ArbiterError::SplitBrainDetected {
                        group_id: group_id.to_string(),
                        details: "STONITH receipt does not match active primary task or token"
                            .to_owned(),
                    });
                }
            }
        }

        let fencing_token = store.next_fencing_token()?;
        let lease_id = LeaseId::new(&format!("lease-{}", self.next_lease_seq)).unwrap_or_default();
        self.next_lease_seq = self.next_lease_seq.saturating_add(1);

        let grant = LeaseGrant {
            lease_id,
            group_id: group_id.clone(),
            primary_task_id: candidate_task.clone(),
            hosting_agent_id: hosting_agent,
            fencing_token,
            expires_at_tick: current_tick.saturating_add(group.lease_ttl_ticks),
        };
        group.current_lease = Some(grant.clone());
        Ok(grant)
    }

    /// Processes a single-wire [`MultiplexedAgentHeartbeat`], renewing active primary leases for all
    /// co-located healthy tasks on `heartbeat.agent_id` in a single pass.
    ///
    /// # Arguments
    ///
    /// * `heartbeat` - Incoming [`MultiplexedAgentHeartbeat`].
    ///
    /// # Returns
    ///
    /// Vector of renewed [`LeaseGrant`]s to push back to the Agent's local `CaaS` cache.
    pub fn process_multiplexed_heartbeat(
        &mut self,
        heartbeat: &MultiplexedAgentHeartbeat,
    ) -> Vec<LeaseGrant> {
        let mut renewed = Vec::new();
        for group in self.groups.values_mut() {
            if let Some(ref mut lease) = group.current_lease {
                if lease.hosting_agent_id == heartbeat.agent_id
                    && lease.is_active(heartbeat.heartbeat_tick)
                    && heartbeat.healthy_tasks.contains(&lease.primary_task_id)
                {
                    lease.expires_at_tick = heartbeat
                        .heartbeat_tick
                        .saturating_add(group.lease_ttl_ticks);
                    renewed.push(lease.clone());
                }
            }
        }
        renewed
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::memory::MemoryStateStore;

    #[test]
    fn test_election_group_registration_and_single_wire_heartbeat() {
        let mut store = MemoryStateStore::new();
        let mut plane = ElectionPlane::new();

        let gid = ElectionGroupId::new("pg-ha-1").unwrap_or_default();
        let t1 = TaskId::new("pg-node-1").unwrap_or_default();
        let t2 = TaskId::new("pg-node-2").unwrap_or_default();
        let a1 = AgentId::new("agent-1").unwrap_or_default();
        let a2 = AgentId::new("agent-2").unwrap_or_default();

        // Empty members or 0 TTL rejected
        assert!(plane.register_group(gid.clone(), vec![], 100).is_err());
        assert!(
            plane
                .register_group(gid.clone(), vec![(t1.clone(), a1.clone())], 0)
                .is_err()
        );

        // Unknown group election rejected
        assert!(
            plane
                .elect_or_promote_primary(&mut store, &gid, &t1, 10, None)
                .is_err()
        );

        assert!(
            plane
                .register_group(
                    gid.clone(),
                    vec![(t1.clone(), a1.clone()), (t2, a2.clone())],
                    100,
                )
                .is_ok()
        );

        // Heartbeat before any primary is elected (covers current_lease == None)
        let hb_before = MultiplexedAgentHeartbeat {
            agent_id: a1.clone(),
            healthy_tasks: vec![t1.clone()],
            heartbeat_tick: 5,
        };
        assert!(plane.process_multiplexed_heartbeat(&hb_before).is_empty());

        // Non-member task rejected
        let non_member = TaskId::new("pg-ghost").unwrap_or_default();
        assert!(
            plane
                .elect_or_promote_primary(&mut store, &gid, &non_member, 10, None)
                .is_err()
        );

        // Initial election of t1 at tick 10 (expires at 110, token = 1)
        let grant1 = plane
            .elect_or_promote_primary(&mut store, &gid, &t1, 10, None)
            .unwrap_or_default();
        assert_eq!(grant1.fencing_token.get(), 1);
        assert_eq!(grant1.expires_at_tick, 110);

        // Single-wire multiplexed heartbeat from agent-1 at tick 50 renews lease until 150
        let hb = MultiplexedAgentHeartbeat {
            agent_id: a1.clone(),
            healthy_tasks: vec![t1.clone()],
            heartbeat_tick: 50,
        };
        let renewed = plane.process_multiplexed_heartbeat(&hb);
        assert_eq!(renewed.len(), 1);
        assert_eq!(renewed.first().map(|g| g.expires_at_tick), Some(150));

        // Heartbeat from different agent, unhealthy task list, or expired tick does not renew
        let hb_other = MultiplexedAgentHeartbeat {
            agent_id: a2,
            healthy_tasks: vec![t1.clone()],
            heartbeat_tick: 60,
        };
        assert!(plane.process_multiplexed_heartbeat(&hb_other).is_empty());

        let hb_unhealthy = MultiplexedAgentHeartbeat {
            agent_id: a1.clone(),
            healthy_tasks: vec![],
            heartbeat_tick: 60,
        };
        assert!(
            plane
                .process_multiplexed_heartbeat(&hb_unhealthy)
                .is_empty()
        );

        let hb_expired = MultiplexedAgentHeartbeat {
            agent_id: a1,
            healthy_tasks: vec![t1],
            heartbeat_tick: 200,
        };
        assert!(plane.process_multiplexed_heartbeat(&hb_expired).is_empty());
    }

    #[test]
    fn test_stonith_fencing_and_split_brain_immunity() {
        let mut store = MemoryStateStore::new();
        let mut plane = ElectionPlane::new();

        let gid = ElectionGroupId::new("mysql-ha").unwrap_or_default();
        let t1 = TaskId::new("mysql-1").unwrap_or_default();
        let t2 = TaskId::new("mysql-2").unwrap_or_default();
        let a1 = AgentId::new("agent-1").unwrap_or_default();
        let a2 = AgentId::new("agent-2").unwrap_or_default();

        let _ = plane.register_group(
            gid.clone(),
            vec![(t1.clone(), a1.clone()), (t2.clone(), a2)],
            100,
        );

        let grant1 = plane
            .elect_or_promote_primary(&mut store, &gid, &t1, 10, None)
            .unwrap_or_default();

        // Attempting to promote t2 at tick 50 (< 110) WITHOUT STONITH receipt -> SplitBrainDetected!
        assert!(
            plane
                .elect_or_promote_primary(&mut store, &gid, &t2, 50, None)
                .is_err()
        );

        // Incomplete STONITH receipts rejected (process=false, storage=false, network=false)
        for (proc_ok, stor_ok, net_ok) in [
            (false, true, true),
            (true, false, true),
            (true, true, false),
        ] {
            let bad_receipt = StonithFenceReceipt {
                fenced_agent_id: a1.clone(),
                fenced_task_id: t1.clone(),
                revoked_token: grant1.fencing_token,
                process_terminated: proc_ok,
                storage_unmounted: stor_ok,
                network_isolated: net_ok,
            };
            assert!(
                plane
                    .elect_or_promote_primary(&mut store, &gid, &t2, 50, Some(&bad_receipt))
                    .is_err()
            );
        }

        // Mismatched task or token in STONITH receipt rejected
        let wrong_task_receipt = StonithFenceReceipt {
            fenced_agent_id: a1.clone(),
            fenced_task_id: t2.clone(),
            revoked_token: grant1.fencing_token,
            process_terminated: true,
            storage_unmounted: true,
            network_isolated: true,
        };
        assert!(
            plane
                .elect_or_promote_primary(&mut store, &gid, &t2, 50, Some(&wrong_task_receipt))
                .is_err()
        );

        let wrong_tok_receipt = StonithFenceReceipt {
            fenced_agent_id: a1.clone(),
            fenced_task_id: t1.clone(),
            revoked_token: FencingToken::new(99).unwrap_or_default(),
            process_terminated: true,
            storage_unmounted: true,
            network_isolated: true,
        };
        assert!(
            plane
                .elect_or_promote_primary(&mut store, &gid, &t2, 50, Some(&wrong_tok_receipt))
                .is_err()
        );

        // Valid complete STONITH receipt allows immediate promotion at tick 50 with token = 2!
        let valid_receipt = StonithFenceReceipt {
            fenced_agent_id: a1,
            fenced_task_id: t1.clone(),
            revoked_token: grant1.fencing_token,
            process_terminated: true,
            storage_unmounted: true,
            network_isolated: true,
        };
        let grant2 = plane
            .elect_or_promote_primary(&mut store, &gid, &t2, 50, Some(&valid_receipt))
            .unwrap_or_default();
        assert_eq!(grant2.fencing_token.get(), 2);
        assert!(grant2.fencing_token > grant1.fencing_token);
        assert!(
            grant1
                .fencing_token
                .validate_against(grant2.fencing_token)
                .is_err()
        );

        // After grant2 expires at tick 150, t1 can be promoted at tick 160 without needing a receipt
        let grant3 = plane
            .elect_or_promote_primary(&mut store, &gid, &t1, 160, None)
            .unwrap_or_default();
        assert_eq!(grant3.fencing_token.get(), 3);

        // Store fault on next_fencing_token propagates cleanly
        store.set_fault(Some(crate::memory::MemoryStoreFault::FailWrites));
        assert!(
            plane
                .elect_or_promote_primary(&mut store, &gid, &t2, 300, None)
                .is_err()
        );
    }

    proptest! {
        #[test]
        fn prop_fencing_tokens_strictly_monotonic(steps in 1..20_usize) {
            let mut store = MemoryStateStore::new();
            let mut plane = ElectionPlane::new();
            let gid = ElectionGroupId::new("etcd-ha").unwrap_or_default();
            let t1 = TaskId::new("etcd-1").unwrap_or_default();
            let a1 = AgentId::new("agent-1").unwrap_or_default();
            let _ = plane.register_group(gid.clone(), vec![(t1.clone(), a1)], 10);

            let mut prev_token = 0_u64;
            let mut tick = 0_u64;
            for _ in 0..steps {
                let grant = plane
                    .elect_or_promote_primary(&mut store, &gid, &t1, tick, None)
                    .unwrap_or_default();
                prop_assert!(grant.fencing_token.get() > prev_token);
                prev_token = grant.fencing_token.get();
                tick += 20;
            }
        }
    }
}
