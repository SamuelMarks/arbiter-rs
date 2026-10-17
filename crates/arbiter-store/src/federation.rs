//! Multi-cluster federation topology, logical cluster multiplexing, and cross-cluster DR failover (`arbiter-store::federation`).
//!
//! Supports:
//! - Running multiple logical clusters ([`ClusterId`]) co-located on shared physical [`AgentId`]s
//!   with strict hardware slice partitioning.
//! - Connecting regional Master quorums into a [`FederationTopology`] ([`FederationId`], [`FederationPeer`]).
//! - Formatting and resolving global federated service discovery records
//!   (`<task>.<service>.<role>.<cluster>.<federation>.arbiter.internal`).
//! - Cross-cluster disaster recovery failover for stateful [`ElectionGroupId`]s when a primary
//!   regional cluster becomes unreachable.

use std::collections::BTreeMap;

use arbiter_core::error::{ArbiterError, ArbiterResult};
use arbiter_core::ids::{
    AgentId, ClusterId, ElectionGroupId, FederationId, FencingToken, RoleName, TaskId,
};
use arbiter_core::resources::ResourceBundle;
use serde::{Deserialize, Serialize};

use crate::traits::StateStore;

/// Co-located logical cluster slice reservation on a shared physical Agent node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogicalClusterSlice {
    /// Logical cluster identifier.
    pub cluster_id: ClusterId,
    /// Physical Agent hosting this slice.
    pub agent_id: AgentId,
    /// Dedicated isolated resource capacity assigned to this logical cluster on `agent_id`.
    pub dedicated_resources: ResourceBundle,
}

/// Remote regional cluster peer in a [`FederationTopology`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederationPeer {
    /// Peer cluster identifier.
    pub cluster_id: ClusterId,
    /// Control-plane QUIC/HTTPS endpoint address.
    pub endpoint: String,
    /// Whether the peer quorum is currently reachable and healthy.
    pub reachable: bool,
    /// Advertised excess/idle resource capacity available for cross-cluster bursting.
    pub advertised_idle_capacity: ResourceBundle,
}

/// Global federated service discovery record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederatedServiceRecord {
    /// Fully-qualified internal DNS name (`<task>.<service>.<role>.<cluster>.<federation>.arbiter.internal`).
    pub fqdn: String,
    /// Target IP or host address.
    pub address: String,
    /// Target port.
    pub port: u16,
}

/// Formats the canonical federated DNS name `<task>.<service>.<role>.<cluster>.<federation>.arbiter.internal`.
///
/// # Arguments
///
/// * `task_id` - Task identifier.
/// * `service_name` - Logical service name.
/// * `role` - Scheduling role name.
/// * `cluster_id` - Cluster identifier.
/// * `federation_id` - Federation fabric identifier.
///
/// # Returns
///
/// Formatted FQDN string.
pub fn format_federated_fqdn(
    task_id: &TaskId,
    service_name: &str,
    role: &RoleName,
    cluster_id: &ClusterId,
    federation_id: &FederationId,
) -> String {
    format!("{task_id}.{service_name}.{role}.{cluster_id}.{federation_id}.arbiter.internal")
}

/// Multi-cluster federation topology, co-located node multiplexer, and DR failover registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederationTopology {
    /// Federation fabric identifier.
    pub federation_id: FederationId,
    /// Registered regional [`FederationPeer`]s keyed by [`ClusterId`].
    peers: BTreeMap<ClusterId, FederationPeer>,
    /// Co-located logical cluster slices per physical [`AgentId`].
    colocated_slices: BTreeMap<AgentId, Vec<LogicalClusterSlice>>,
    /// Global service discovery records keyed by FQDN.
    dns_records: BTreeMap<String, FederatedServiceRecord>,
    /// Active primary cluster and monotonic fencing token for federated stateful [`ElectionGroupId`]s.
    federated_elections: BTreeMap<ElectionGroupId, (ClusterId, FencingToken)>,
}

impl FederationTopology {
    /// Creates a new [`FederationTopology`] for `federation_id`.
    ///
    /// # Arguments
    ///
    /// * `federation_id` - Unique [`FederationId`].
    ///
    /// # Returns
    ///
    /// Empty [`FederationTopology`].
    pub const fn new(federation_id: FederationId) -> Self {
        Self {
            federation_id,
            peers: BTreeMap::new(),
            colocated_slices: BTreeMap::new(),
            dns_records: BTreeMap::new(),
            federated_elections: BTreeMap::new(),
        }
    }

    /// Registers or updates a [`FederationPeer`].
    ///
    /// # Arguments
    ///
    /// * `peer` - [`FederationPeer`] descriptor.
    pub fn upsert_peer(&mut self, peer: FederationPeer) {
        self.peers.insert(peer.cluster_id.clone(), peer);
    }

    /// Returns a reference to the map of registered [`FederationPeer`]s.
    ///
    /// # Returns
    ///
    /// Reference to `BTreeMap<ClusterId, FederationPeer>`.
    pub const fn peers(&self) -> &BTreeMap<ClusterId, FederationPeer> {
        &self.peers
    }

    /// Allocates a co-located [`LogicalClusterSlice`] on a shared physical Agent node, ensuring
    /// the sum of all co-located logical cluster slices does not exceed `physical_agent_capacity`.
    ///
    /// # Arguments
    ///
    /// * `slice` - Requested [`LogicalClusterSlice`].
    /// * `physical_agent_capacity` - Total hardware [`ResourceBundle`] of `slice.agent_id`.
    ///
    /// # Returns
    ///
    /// `Ok(())` if the slice fits alongside existing co-located logical clusters on the Agent.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::InsufficientResources`] if the combined logical cluster slices
    /// would exceed `physical_agent_capacity`.
    pub fn register_colocated_slice(
        &mut self,
        slice: LogicalClusterSlice,
        physical_agent_capacity: &ResourceBundle,
    ) -> ArbiterResult<()> {
        let existing = self
            .colocated_slices
            .entry(slice.agent_id.clone())
            .or_default();

        let mut total_used = slice.dedicated_resources.clone();
        for s in existing.iter() {
            total_used = total_used.try_add(&s.dedicated_resources)?;
        }

        if !physical_agent_capacity.contains(&total_used) {
            return Err(ArbiterError::InsufficientResources {
                resource: "physical_agent_colocation".to_owned(),
                requested: total_used.cpu.get(),
                available: physical_agent_capacity.cpu.get(),
            });
        }

        existing.push(slice);
        Ok(())
    }

    /// Publishes a global federated DNS service discovery record.
    ///
    /// # Arguments
    ///
    /// * `task_id` - Task identifier.
    /// * `service_name` - Service name.
    /// * `role` - Role name.
    /// * `cluster_id` - Hosting cluster identifier.
    /// * `address` - IP or hostname.
    /// * `port` - Service port.
    ///
    /// # Returns
    ///
    /// Registered [`FederatedServiceRecord`].
    pub fn register_service_record(
        &mut self,
        task_id: &TaskId,
        service_name: &str,
        role: &RoleName,
        cluster_id: &ClusterId,
        address: String,
        port: u16,
    ) -> FederatedServiceRecord {
        let fqdn =
            format_federated_fqdn(task_id, service_name, role, cluster_id, &self.federation_id);
        let record = FederatedServiceRecord {
            fqdn: fqdn.clone(),
            address,
            port,
        };
        self.dns_records.insert(fqdn, record.clone());
        record
    }

    /// Resolves a federated internal DNS FQDN.
    ///
    /// # Arguments
    ///
    /// * `fqdn` - Fully-qualified domain name.
    ///
    /// # Returns
    ///
    /// Optional reference to [`FederatedServiceRecord`].
    pub fn resolve_fqdn(&self, fqdn: &str) -> Option<&FederatedServiceRecord> {
        self.dns_records.get(fqdn)
    }

    /// Performs a cross-cluster disaster-recovery (DR) failover for `group_id` to `target_cluster`,
    /// issuing a new monotonic [`FencingToken`] from `store`.
    ///
    /// # Arguments
    ///
    /// * `store` - Consensus [`StateStore`] issuing the monotonic token.
    /// * `group_id` - Stateful [`ElectionGroupId`] failing over.
    /// * `target_cluster` - Standby [`ClusterId`] being promoted to primary.
    ///
    /// # Returns
    ///
    /// Issued [`FencingToken`] for the promoted cluster.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::FederationPeerUnreachable`] if `target_cluster` is unknown or unreachable.
    pub fn failover_election_group<S: StateStore>(
        &mut self,
        store: &mut S,
        group_id: ElectionGroupId,
        target_cluster: &ClusterId,
    ) -> ArbiterResult<FencingToken> {
        let Some(peer) = self.peers.get(target_cluster) else {
            return Err(ArbiterError::FederationPeerUnreachable {
                peer_cluster: target_cluster.to_string(),
                reason: "peer cluster is not registered in federation topology".to_owned(),
            });
        };
        if !peer.reachable {
            return Err(ArbiterError::FederationPeerUnreachable {
                peer_cluster: target_cluster.to_string(),
                reason: "peer cluster quorum is marked unreachable".to_owned(),
            });
        }

        let token = store.next_fencing_token()?;
        self.federated_elections
            .insert(group_id, (target_cluster.clone(), token));
        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use arbiter_core::units::{Bytes, Millicores};

    use super::*;
    use crate::memory::MemoryStateStore;

    fn make_bundle(cpu_m: u64, mem_b: u64) -> ResourceBundle {
        ResourceBundle {
            cpu: Millicores::new(cpu_m),
            memory: Bytes::new(mem_b),
            ..ResourceBundle::zero()
        }
    }

    #[test]
    fn test_colocated_logical_clusters_dns_and_dr_failover() {
        let mut store = MemoryStateStore::new();
        let fed_id = FederationId::new("global-fed").unwrap_or_default();
        let mut topo = FederationTopology::new(fed_id);

        let c_east = ClusterId::new("us-east-1").unwrap_or_default();
        let c_west = ClusterId::new("us-west-2").unwrap_or_default();
        let c_unknown = ClusterId::new("eu-central-1").unwrap_or_default();
        let agent1 = AgentId::new("agent-shared-1").unwrap_or_default();

        // Co-locate two logical clusters (us-east-1 and us-west-2) on physical agent-shared-1 (capacity 32_000m)
        let phys_cap = make_bundle(32_000, 64_000);
        assert!(
            topo.register_colocated_slice(
                LogicalClusterSlice {
                    cluster_id: c_east.clone(),
                    agent_id: agent1.clone(),
                    dedicated_resources: make_bundle(16_000, 32_000),
                },
                &phys_cap,
            )
            .is_ok()
        );
        assert!(
            topo.register_colocated_slice(
                LogicalClusterSlice {
                    cluster_id: c_west.clone(),
                    agent_id: agent1.clone(),
                    dedicated_resources: make_bundle(16_000, 32_000),
                },
                &phys_cap,
            )
            .is_ok()
        );

        // Third slice exceeding 32_000m rejected
        assert!(
            topo.register_colocated_slice(
                LogicalClusterSlice {
                    cluster_id: c_unknown.clone(),
                    agent_id: agent1.clone(),
                    dedicated_resources: make_bundle(4_000, 1024),
                },
                &phys_cap,
            )
            .is_err()
        );

        // Overflow on slice addition rejected
        assert!(
            topo.register_colocated_slice(
                LogicalClusterSlice {
                    cluster_id: c_unknown.clone(),
                    agent_id: agent1,
                    dedicated_resources: make_bundle(u64::MAX, 0),
                },
                &phys_cap,
            )
            .is_err()
        );

        // Service discovery FQDN registration & lookup
        let task_id = TaskId::new("pg-0").unwrap_or_default();
        let role = RoleName::new("db").unwrap_or_default();
        let rec = topo.register_service_record(
            &task_id,
            "postgres",
            &role,
            &c_east,
            "10.0.1.15".to_owned(),
            5432,
        );
        assert_eq!(
            rec.fqdn,
            "pg-0.postgres.db.us-east-1.global-fed.arbiter.internal"
        );
        assert_eq!(topo.resolve_fqdn(&rec.fqdn), Some(&rec));
        assert!(topo.resolve_fqdn("nonexistent.arbiter.internal").is_none());

        // Peer registration & DR failover
        topo.upsert_peer(FederationPeer {
            cluster_id: c_east.clone(),
            endpoint: "https://east:5050".to_owned(),
            reachable: false,
            advertised_idle_capacity: ResourceBundle::zero(),
        });
        topo.upsert_peer(FederationPeer {
            cluster_id: c_west.clone(),
            endpoint: "https://west:5050".to_owned(),
            reachable: true,
            advertised_idle_capacity: make_bundle(64_000, 128_000),
        });
        assert_eq!(topo.peers().len(), 2);

        let gid = ElectionGroupId::new("pg-global-ha").unwrap_or_default();
        // Failover to unknown cluster -> FederationPeerUnreachable
        assert!(
            topo.failover_election_group(&mut store, gid.clone(), &c_unknown)
                .is_err()
        );
        // Failover to unreachable c_east -> FederationPeerUnreachable
        assert!(
            topo.failover_election_group(&mut store, gid.clone(), &c_east)
                .is_err()
        );
        // Failover to healthy c_west -> succeeds with token 1
        let tok = topo.failover_election_group(&mut store, gid.clone(), &c_west);
        assert_eq!(tok.map(FencingToken::get), Ok(1));

        // Store fault during failover
        store.set_fault(Some(crate::memory::MemoryStoreFault::FailWrites));
        assert!(
            topo.failover_election_group(&mut store, gid, &c_west)
                .is_err()
        );
    }
}
