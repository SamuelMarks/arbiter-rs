//! Zero-packet local lease verification cache and `CaaS` socket handler (`arbiter-agent::caas`).
//!
//! Exposes a local Unix Domain Socket / Windows Named Pipe and loopback endpoint abstraction on
//! each Agent so co-located stateful workloads (Postgres, `MySQL`, etcd, Redis) can verify
//! *"Am I still the primary for `ElectionGroupId`?"* in nanoseconds against the Agent's active
//! Master lease with **zero extra network packets**.

use std::collections::BTreeMap;

use arbiter_core::error::{ArbiterError, ArbiterResult};
use arbiter_core::ids::{AgentId, ElectionGroupId, FencingToken, TaskId};
use arbiter_store::election::LeaseGrant;
use serde::{Deserialize, Serialize};

/// Response returned to a local workload querying the Agent's `CaaS` local socket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalLeaseVerification {
    /// Election group queried.
    pub group_id: ElectionGroupId,
    /// Task verified as primary.
    pub primary_task_id: TaskId,
    /// Active monotonic fencing token (`FencingToken`).
    pub fencing_token: FencingToken,
    /// Remaining ticks until the local lease expires if not renewed by the Agent's Master heartbeat.
    pub remaining_ttl_ticks: u64,
}

/// Zero-packet local `CaaS` lease cache maintained by an Agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentCaasLeaseCache {
    /// Hosting Agent identifier.
    agent_id: AgentId,
    /// Monotonic tick until which the Agent's own control-plane heartbeat lease with the Master is valid.
    agent_master_lease_until_tick: u64,
    /// Cached primary [`LeaseGrant`]s for co-located workloads keyed by [`ElectionGroupId`].
    group_leases: BTreeMap<ElectionGroupId, LeaseGrant>,
}

impl AgentCaasLeaseCache {
    /// Creates a new [`AgentCaasLeaseCache`] for `agent_id`.
    ///
    /// # Arguments
    ///
    /// * `agent_id` - Hosting [`AgentId`].
    /// * `agent_master_lease_until_tick` - Initial Master heartbeat lease expiration tick.
    ///
    /// # Returns
    ///
    /// Initialized [`AgentCaasLeaseCache`].
    pub const fn new(agent_id: AgentId, agent_master_lease_until_tick: u64) -> Self {
        Self {
            agent_id,
            agent_master_lease_until_tick,
            group_leases: BTreeMap::new(),
        }
    }

    /// Updates the Agent's Master lease expiration and refreshes co-located [`LeaseGrant`]s
    /// received from a single-wire Master heartbeat response.
    ///
    /// # Arguments
    ///
    /// * `new_agent_lease_until_tick` - Updated Master lease expiration tick.
    /// * `renewed_grants` - Slice of renewed [`LeaseGrant`]s from the Master.
    pub fn apply_heartbeat_renewals(
        &mut self,
        new_agent_lease_until_tick: u64,
        renewed_grants: &[LeaseGrant],
    ) {
        self.agent_master_lease_until_tick = new_agent_lease_until_tick;
        for grant in renewed_grants {
            if grant.hosting_agent_id == self.agent_id {
                self.group_leases
                    .insert(grant.group_id.clone(), grant.clone());
            }
        }
    }

    /// Immediately revokes a cached [`ElectionGroupId`] lease on this Agent (used during synchronous STONITH fencing).
    ///
    /// # Arguments
    ///
    /// * `group_id` - Election group to revoke.
    ///
    /// # Returns
    ///
    /// The revoked [`LeaseGrant`] if one was cached.
    pub fn revoke_local_lease(&mut self, group_id: &ElectionGroupId) -> Option<LeaseGrant> {
        self.group_leases.remove(group_id)
    }

    /// Verifies in-memory (zero network packets) whether `task_id` holds an active primary lease
    /// for `group_id` at `current_tick` with a token at least as new as `presented_token`.
    ///
    /// Both the Agent's own Master heartbeat lease AND the workload's [`LeaseGrant`] must be
    /// unexpired at `current_tick`.
    ///
    /// # Arguments
    ///
    /// * `group_id` - Target [`ElectionGroupId`].
    /// * `task_id` - Local workload [`TaskId`] claiming leadership.
    /// * `presented_token` - [`FencingToken`] held by the local workload.
    /// * `current_tick` - Current monotonic tick.
    ///
    /// # Returns
    ///
    /// [`LocalLeaseVerification`] confirming primary status and remaining TTL.
    ///
    /// # Errors
    ///
    /// Returns:
    /// - [`ArbiterError::LeaseExpired`] if the Agent's Master lease or the group's lease has expired.
    /// - [`ArbiterError::StoreReadError`] if no lease is cached for `group_id`.
    /// - [`ArbiterError::AuthorizationDenied`] if `task_id` is not the elected primary for `group_id`.
    /// - [`ArbiterError::FencingTokenStale`] if `presented_token < grant.fencing_token`.
    pub fn verify_local_primary(
        &self,
        group_id: &ElectionGroupId,
        task_id: &TaskId,
        presented_token: FencingToken,
        current_tick: u64,
    ) -> ArbiterResult<LocalLeaseVerification> {
        if current_tick >= self.agent_master_lease_until_tick {
            return Err(ArbiterError::LeaseExpired {
                lease_id: format!("agent-master-lease-{}", self.agent_id),
                expired_at_tick: self.agent_master_lease_until_tick,
            });
        }

        let Some(grant) = self.group_leases.get(group_id) else {
            return Err(ArbiterError::StoreReadError {
                key: group_id.to_string(),
                reason: "no local CaaS lease cached for election group".to_owned(),
            });
        };

        if !grant.is_active(current_tick) {
            return Err(ArbiterError::LeaseExpired {
                lease_id: grant.lease_id.to_string(),
                expired_at_tick: grant.expires_at_tick,
            });
        }

        if &grant.primary_task_id != task_id {
            return Err(ArbiterError::AuthorizationDenied {
                principal: task_id.to_string(),
                action: "VerifyPrimaryLease".to_owned(),
                resource: group_id.to_string(),
            });
        }

        presented_token.validate_against(grant.fencing_token)?;

        let effective_expiry = grant
            .expires_at_tick
            .min(self.agent_master_lease_until_tick);
        let remaining_ttl_ticks = effective_expiry.saturating_sub(current_tick);

        Ok(LocalLeaseVerification {
            group_id: group_id.clone(),
            primary_task_id: task_id.clone(),
            fencing_token: grant.fencing_token,
            remaining_ttl_ticks,
        })
    }
}

#[cfg(test)]
mod tests {
    use arbiter_core::ids::LeaseId;

    use super::*;

    #[test]
    fn test_zero_packet_local_lease_verification() {
        let a1 = AgentId::new("agent-1").unwrap_or_default();
        let a2 = AgentId::new("agent-2").unwrap_or_default();
        let gid = ElectionGroupId::new("pg-ha").unwrap_or_default();
        let t1 = TaskId::new("pg-primary").unwrap_or_default();
        let t2 = TaskId::new("pg-standby").unwrap_or_default();
        let tok1 = FencingToken::new(1).unwrap_or_default();
        let tok2 = FencingToken::new(2).unwrap_or_default();

        let mut cache = AgentCaasLeaseCache::new(a1.clone(), 200);

        // Missing group lease -> StoreReadError
        assert!(cache.verify_local_primary(&gid, &t1, tok1, 50).is_err());

        let grant = LeaseGrant {
            lease_id: LeaseId::new("lease-1").unwrap_or_default(),
            group_id: gid.clone(),
            primary_task_id: t1.clone(),
            hosting_agent_id: a1,
            fencing_token: tok2,
            expires_at_tick: 150,
        };
        let other_agent_grant = LeaseGrant {
            lease_id: LeaseId::new("lease-2").unwrap_or_default(),
            group_id: ElectionGroupId::new("other").unwrap_or_default(),
            primary_task_id: t2.clone(),
            hosting_agent_id: a2,
            fencing_token: tok2,
            expires_at_tick: 150,
        };

        cache.apply_heartbeat_renewals(200, &[grant, other_agent_grant]);

        // Valid zero-packet local verification
        let verified = cache.verify_local_primary(&gid, &t1, tok2, 50);
        assert!(verified.is_ok());
        assert_eq!(
            verified.map(|v| v.remaining_ttl_ticks),
            Ok(100) // min(150, 200) - 50 = 100
        );

        // Stale fencing token (tok1 < tok2) -> FencingTokenStale
        assert_eq!(
            cache.verify_local_primary(&gid, &t1, tok1, 50),
            Err(ArbiterError::FencingTokenStale {
                presented_token: 1,
                current_token: 2,
            })
        );

        // Wrong task claiming primary -> AuthorizationDenied
        assert!(cache.verify_local_primary(&gid, &t2, tok2, 50).is_err());

        // Group lease expired at tick 160 (< agent lease 200) -> LeaseExpired
        assert!(cache.verify_local_primary(&gid, &t1, tok2, 160).is_err());

        // Agent Master lease expired at tick 250 -> LeaseExpired
        assert!(cache.verify_local_primary(&gid, &t1, tok2, 250).is_err());

        // Revoke lease during STONITH fencing
        assert!(cache.revoke_local_lease(&gid).is_some());
        assert!(cache.verify_local_primary(&gid, &t1, tok2, 50).is_err());
    }
}
