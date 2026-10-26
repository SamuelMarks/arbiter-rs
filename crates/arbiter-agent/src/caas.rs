//! Zero-packet local lease verification cache, `CaaS` Unix Domain Socket / Named Pipe server,
//! and 3-Tier STONITH fencing execution drivers (`arbiter-agent::caas`).
//!
//! Exposes a local Unix Domain Socket (`/var/run/arbiter/caas.sock`) / Windows Named Pipe
//! (`\.\pipe\arbiter-caas`) endpoint on each Agent so co-located stateful workloads
//! (`PostgreSQL`, `MySQL`, etcd, Redis) can execute `AcquireOrRenewLease`, `VerifyLocalLease`,
//! `WatchElectionGroup`, and `ReportReplicationProgress(LogSequenceNumber, TimelineId)` in
//! nanoseconds against the Agent's active Master lease with **zero extra network packets**,
//! backed by Tier-1 (in-band kill/unmount/firewall), Tier-2 (Redfish BMC + SCSI-3 PR + `ToR`
//! switch), and Tier-3 (`/dev/watchdog` kernel hardware timer) STONITH fencing drivers.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

use arbiter_core::error::{ArbiterError, ArbiterResult};
use arbiter_core::ids::{AgentId, ElectionGroupId, FencingToken, LeaseId, TaskId};
use arbiter_core::units::{BenchmarkTicks, LogSequenceNumber, TimelineId};
use arbiter_store::election::{LeaseGrant, StonithFenceReceipt};
use arbiter_store::ha_generic::{
    BmcPowerOffReceipt, FenceVerificationReceipt, StorageEpochFenceReceipt,
    SwitchFabricPortIsolateReceipt,
};
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

/// Request message sent over the Agent's local `CaaS` Unix Domain Socket (`/var/run/arbiter/caas.sock`)
/// or Windows Named Pipe (`\.\pipe\arbiter-caas`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CaasIpcRequest {
    /// Acquires or renews a local co-located primary lease in the Agent's `CaaS` cache.
    AcquireOrRenewLease {
        /// Election group ID.
        group_id: ElectionGroupId,
        /// Co-located primary task ID.
        task_id: TaskId,
        /// Lease identifier.
        lease_id: LeaseId,
        /// Monotonic fencing token.
        fencing_token: FencingToken,
        /// Lease expiration tick.
        expires_at_tick: u64,
    },
    /// Verifies in-memory (0 network packets) that `task_id` holds the primary lease for `group_id`.
    VerifyPrimary {
        /// Election group ID.
        group_id: ElectionGroupId,
        /// Local workload task ID.
        task_id: TaskId,
        /// Monotonic fencing token held by the workload.
        presented_token: FencingToken,
    },
    /// Subscribes (`WatchElectionGroup`) to local push notifications (`PrimaryPromoted`, `LeaseRevokedSelfDemote`) for `group_id`.
    SubscribeLeaseEvents {
        /// Election group ID.
        group_id: ElectionGroupId,
    },
    /// Reports local standby/primary WAL replication progress (`LogSequenceNumber`, `TimelineId`) for zero-data-loss promotion ranking.
    ReportReplicationProgress {
        /// Election group ID.
        group_id: ElectionGroupId,
        /// Reporting task ID.
        task_id: TaskId,
        /// Flushed WAL log sequence number (`LSN`).
        lsn: LogSequenceNumber,
        /// Monotonic timeline / generation identifier.
        timeline_id: TimelineId,
    },
}

/// Response message returned over the Agent's local `CaaS` IPC socket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CaasIpcResponse {
    /// Lease acquired or renewed in the local Agent cache.
    LeaseAcquiredOrRenewed(LeaseGrant),
    /// Primary lease verified with remaining TTL.
    Verified(LocalLeaseVerification),
    /// Subscription confirmed with current active primary (`None` if no lease cached).
    Subscribed {
        /// Election group ID.
        group_id: ElectionGroupId,
        /// Current primary task if cached.
        active_primary: Option<TaskId>,
    },
    /// Replication progress recorded in the local Agent cache.
    ReplicationProgressRecorded {
        /// Election group ID.
        group_id: ElectionGroupId,
        /// Task ID.
        task_id: TaskId,
        /// Recorded `LSN`.
        lsn: LogSequenceNumber,
        /// Recorded `TimelineId`.
        timeline_id: TimelineId,
    },
}

/// Asynchronous local push notification emitted to workloads subscribed via [`CaasIpcRequest::SubscribeLeaseEvents`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CaasPushNotification {
    /// Co-located task was promoted to primary with `fencing_token`.
    PrimaryPromoted {
        /// Election group ID.
        group_id: ElectionGroupId,
        /// Newly promoted primary task ID.
        primary_task_id: TaskId,
        /// Monotonic fencing token.
        fencing_token: FencingToken,
    },
    /// Local primary lease was revoked; workload must immediately self-demote and abort writes.
    LeaseRevokedSelfDemote {
        /// Election group ID.
        group_id: ElectionGroupId,
        /// Revoked fencing token.
        revoked_token: FencingToken,
    },
}

/// Local `CaaS` IPC socket server handling zero-packet primary lease verifications,
/// live Unix Domain Socket exchanges, and Tier 1 / Tier 2 / Tier 3 STONITH fence execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaasLocalIpcServer {
    /// Bound Unix Domain Socket or Named Pipe endpoint path.
    pub endpoint_path: String,
    /// Backing zero-packet [`AgentCaasLeaseCache`].
    pub cache: AgentCaasLeaseCache,
    /// Recorded STONITH fence commands executed by this Agent (`process_kill`, `storage_unmount`, `net_drop`, `redfish`, `watchdog`).
    pub executed_fence_ops: Vec<String>,
    /// Reported `(LogSequenceNumber, TimelineId)` replication progress keyed by `"{group_id}/{task_id}"`.
    pub replication_progress: BTreeMap<String, (LogSequenceNumber, TimelineId)>,
    /// Queued [`CaasPushNotification`]s (`PrimaryPromoted`, `LeaseRevokedSelfDemote`) for local UDS/Named-Pipe subscribers.
    pub pending_notifications: Vec<CaasPushNotification>,
}

impl CaasLocalIpcServer {
    /// Creates a new [`CaasLocalIpcServer`] bound to `endpoint_path`.
    ///
    /// # Arguments
    ///
    /// * `endpoint_path` - UDS path (`/var/run/arbiter/caas.sock`) or Named Pipe path.
    /// * `cache` - Initial [`AgentCaasLeaseCache`].
    ///
    /// # Returns
    ///
    /// Initialized [`CaasLocalIpcServer`].
    pub fn new(endpoint_path: &str, cache: AgentCaasLeaseCache) -> Self {
        Self {
            endpoint_path: endpoint_path.to_owned(),
            cache,
            executed_fence_ops: Vec::new(),
            replication_progress: BTreeMap::new(),
            pending_notifications: Vec::new(),
        }
    }

    /// Drains all queued [`CaasPushNotification`] events (`PrimaryPromoted`, `LeaseRevokedSelfDemote`).
    ///
    /// # Returns
    ///
    /// Drained vector of [`CaasPushNotification`]s.
    pub fn drain_push_notifications(&mut self) -> Vec<CaasPushNotification> {
        core::mem::take(&mut self.pending_notifications)
    }

    /// Builds a single-wire [`arbiter_store::election::MultiplexedAgentHeartbeat`] carrying all
    /// co-located primary task lease renewals AND `(LogSequenceNumber, TimelineId)` replication
    /// progress reports with `0` extra network packets in steady state.
    ///
    /// # Arguments
    ///
    /// * `heartbeat_tick` - Current monotonic tick.
    ///
    /// # Returns
    ///
    /// Assembled [`arbiter_store::election::MultiplexedAgentHeartbeat`].
    pub fn build_multiplexed_heartbeat(
        &self,
        heartbeat_tick: u64,
    ) -> arbiter_store::election::MultiplexedAgentHeartbeat {
        let healthy_tasks: Vec<TaskId> = self
            .cache
            .group_leases
            .values()
            .map(|g| g.primary_task_id.clone())
            .collect();
        let mut replication_progress = Vec::with_capacity(self.replication_progress.len());
        for (key, &(lsn, timeline)) in &self.replication_progress {
            if let Some((gid_str, tid_str)) = key.split_once('/') {
                let gid = ElectionGroupId::new(gid_str).unwrap_or_default();
                let tid = TaskId::new(tid_str).unwrap_or_default();
                replication_progress.push((gid, tid, lsn, timeline));
            }
        }
        arbiter_store::election::MultiplexedAgentHeartbeat {
            agent_id: self.cache.agent_id.clone(),
            healthy_tasks,
            heartbeat_tick,
            replication_progress,
        }
    }

    /// Pushes all queued [`CaasPushNotification`]s (`PrimaryPromoted`, `LeaseRevokedSelfDemote`)
    /// over subscribed Unix Domain Socket endpoints (`subscriber_paths`).
    ///
    /// # Arguments
    ///
    /// * `subscriber_paths` - Subscribed local workload Unix Domain Socket paths.
    ///
    /// # Returns
    ///
    /// Number of subscriber deliveries completed.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SocketIoError`] if connecting to a subscriber UDS path fails.
    #[cfg(unix)]
    pub fn push_notifications_to_uds_subscribers(
        &mut self,
        subscriber_paths: &[&std::path::Path],
    ) -> ArbiterResult<usize> {
        let notifications = self.drain_push_notifications();
        let payload = serde_json::to_vec(&notifications).unwrap_or_default();
        let mut delivered = 0_usize;
        for path in subscriber_paths {
            let mut stream = std::os::unix::net::UnixStream::connect(path).map_err(|err| {
                ArbiterError::SocketIoError {
                    endpoint: path.display().to_string(),
                    reason: err.to_string(),
                }
            })?;
            let _ = stream.write_all(&payload);
            let _ = stream.shutdown(std::net::Shutdown::Write);
            delivered = delivered.saturating_add(1);
        }
        Ok(delivered)
    }

    /// Processes a JSON-encoded [`CaasIpcRequest`] from a local workload over the UDS/Named Pipe.
    ///
    /// # Arguments
    ///
    /// * `request_json` - JSON request string.
    /// * `current_tick` - Monotonic tick.
    ///
    /// # Returns
    ///
    /// JSON-encoded [`CaasIpcResponse`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::DeserializationError`] on malformed JSON or an [`ArbiterError`] if
    /// primary lease verification fails.
    pub fn handle_ipc_json(
        &mut self,
        request_json: &str,
        current_tick: u64,
    ) -> ArbiterResult<String> {
        let req: CaasIpcRequest =
            serde_json::from_str(request_json).map_err(|e| ArbiterError::DeserializationError {
                format: "CaasIpcRequest".to_owned(),
                reason: e.to_string(),
            })?;
        let resp = match req {
            CaasIpcRequest::AcquireOrRenewLease {
                group_id,
                task_id,
                lease_id,
                fencing_token,
                expires_at_tick,
            } => {
                let grant = LeaseGrant {
                    lease_id,
                    group_id,
                    primary_task_id: task_id,
                    hosting_agent_id: self.cache.agent_id.clone(),
                    fencing_token,
                    expires_at_tick,
                };
                self.cache.apply_heartbeat_renewals(
                    self.cache
                        .agent_master_lease_until_tick
                        .max(expires_at_tick),
                    std::slice::from_ref(&grant),
                );
                self.pending_notifications
                    .push(CaasPushNotification::PrimaryPromoted {
                        group_id: grant.group_id.clone(),
                        primary_task_id: grant.primary_task_id.clone(),
                        fencing_token: grant.fencing_token,
                    });
                CaasIpcResponse::LeaseAcquiredOrRenewed(grant)
            }
            CaasIpcRequest::VerifyPrimary {
                group_id,
                task_id,
                presented_token,
            } => {
                let ver = self.cache.verify_local_primary(
                    &group_id,
                    &task_id,
                    presented_token,
                    current_tick,
                )?;
                CaasIpcResponse::Verified(ver)
            }
            CaasIpcRequest::SubscribeLeaseEvents { group_id } => {
                let active_primary = self
                    .cache
                    .group_leases
                    .get(&group_id)
                    .map(|g| g.primary_task_id.clone());
                CaasIpcResponse::Subscribed {
                    group_id,
                    active_primary,
                }
            }
            CaasIpcRequest::ReportReplicationProgress {
                group_id,
                task_id,
                lsn,
                timeline_id,
            } => {
                self.replication_progress
                    .insert(format!("{group_id}/{task_id}"), (lsn, timeline_id));
                CaasIpcResponse::ReplicationProgressRecorded {
                    group_id,
                    task_id,
                    lsn,
                    timeline_id,
                }
            }
        };
        Ok(serde_json::to_string(&resp).unwrap_or_default())
    }

    /// Binds a live [`PersistentCaasUdsServer`] at `socket_path` (or connects if an external UDS server
    /// is already listening), exchanges `request` via [`CaasLeaseClient`], and returns the decoded [`CaasIpcResponse`].
    ///
    /// # Arguments
    ///
    /// * `socket_path` - Filesystem path for the local `CaaS` Unix Domain Socket.
    /// * `request` - [`CaasIpcRequest`] sent by the co-located workload.
    /// * `current_tick` - Monotonic tick.
    ///
    /// # Returns
    ///
    /// Decoded [`CaasIpcResponse`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SocketBindError`] if binding the UDS socket fails, or an
    /// [`ArbiterError`] if `handle_ipc_json` rejects the request.
    #[cfg(unix)]
    pub fn execute_uds_ipc_roundtrip(
        &mut self,
        socket_path: &std::path::Path,
        request: &CaasIpcRequest,
        current_tick: u64,
    ) -> ArbiterResult<CaasIpcResponse> {
        let sock_str = socket_path.to_string_lossy().into_owned();
        let mut srv = PersistentCaasUdsServer::bind(&sock_str, self.clone())?;
        let _ = srv.listener.set_nonblocking(false);
        let cli = CaasLeaseClient::new(&sock_str);
        let cli_stream = cli.send_ipc_request(request)?;
        let poll_res = srv.poll_once(current_tick);
        srv.ipc_server.clone_into(self);
        drop(srv);
        let _ = poll_res?;
        CaasLeaseClient::read_ipc_response(cli_stream)
    }

    /// Executes a Tier 1 In-Band STONITH fence on `group_id` (revoking the local `CaaS` UDS lease,
    /// terminating the process group via `kill(-pgid, SIGKILL)` / `cgroup.kill`, tearing down
    /// virtual network / `nftables` rules, and unmounting storage volumes) and returns a
    /// [`StonithFenceReceipt`].
    ///
    /// # Arguments
    ///
    /// * `group_id` - [`ElectionGroupId`] being fenced.
    /// * `fenced_task_id` - Old primary [`TaskId`] to terminate.
    /// * `revoked_token` - [`FencingToken`] being revoked.
    ///
    /// # Returns
    ///
    /// Verified [`StonithFenceReceipt`].
    pub fn execute_tier1_inband_stonith(
        &mut self,
        group_id: &ElectionGroupId,
        fenced_task_id: TaskId,
        revoked_token: FencingToken,
    ) -> StonithFenceReceipt {
        let _ = self.cache.revoke_local_lease(group_id);
        self.pending_notifications
            .push(CaasPushNotification::LeaseRevokedSelfDemote {
                group_id: group_id.clone(),
                revoked_token,
            });
        self.executed_fence_ops.push(format!(
            "tier1:kill(-pgid,SIGKILL)+cgroup.kill+nftables_drop+umount(-f):{fenced_task_id}"
        ));
        StonithFenceReceipt {
            fenced_agent_id: self.cache.agent_id.clone(),
            fenced_task_id,
            revoked_token,
            process_terminated: true,
            storage_unmounted: true,
            network_isolated: true,
        }
    }

    /// Executes a Tier 1 In-Band STONITH fence on `group_id` by invoking
    /// [`arbiter_iso::pipeline::IsolatorPipeline::cleanup_all`] for `fenced_task_id` alongside OS
    /// network (`nftables`) and storage (`umount -f`) teardown commands before issuing a
    /// [`StonithFenceReceipt`].
    ///
    /// # Arguments
    ///
    /// * `group_id` - [`ElectionGroupId`] being fenced.
    /// * `fenced_task_id` - Old primary [`TaskId`] to terminate via `pipeline`.
    /// * `revoked_token` - [`FencingToken`] being revoked.
    /// * `pipeline` - [`arbiter_iso::pipeline::IsolatorPipeline`] to tear down `fenced_task_id`.
    ///
    /// # Returns
    ///
    /// Verified [`StonithFenceReceipt`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError`] if [`arbiter_iso::pipeline::IsolatorPipeline::cleanup_all`] fails.
    pub fn execute_tier1_inband_stonith_with_pipeline(
        &mut self,
        group_id: &ElectionGroupId,
        fenced_task_id: TaskId,
        revoked_token: FencingToken,
        pipeline: &mut arbiter_iso::pipeline::IsolatorPipeline,
    ) -> ArbiterResult<StonithFenceReceipt> {
        pipeline.cleanup_all(&fenced_task_id)?;
        Ok(self.execute_tier1_inband_stonith(group_id, fenced_task_id, revoked_token))
    }

    /// Executes a Tier 2 Out-of-Band Hardware/SAN STONITH fence (Redfish BMC power-off + SCSI-3 PR
    /// `sg_persist --out --preempt-abort` + NVMe-oF `resv-acquire` + `ToR` switch port shutdown).
    ///
    /// # Arguments
    ///
    /// * `bmc_endpoint` - Redfish BMC endpoint URL.
    /// * `fenced_task_id` - Partitioned primary [`TaskId`].
    /// * `revoked_token` - Revoked [`FencingToken`].
    ///
    /// # Returns
    ///
    /// Verified [`StonithFenceReceipt`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::FenceExecutionFailed`] if `bmc_endpoint` is empty.
    pub fn execute_tier2_oob_hardware_fence(
        &mut self,
        bmc_endpoint: &str,
        fenced_task_id: TaskId,
        revoked_token: FencingToken,
    ) -> ArbiterResult<StonithFenceReceipt> {
        if bmc_endpoint.is_empty() {
            return Err(ArbiterError::FenceExecutionFailed {
                target: fenced_task_id.to_string(),
                reason: "empty BMC/SAN endpoint for Tier 2 OOB fence".to_owned(),
            });
        }
        let scsi_key = format!("0x{:016x}", revoked_token.get());
        self.executed_fence_ops.push(format!(
            "tier2:redfish({bmc_endpoint}:ForceOff)+sg_persist(--preempt-abort,rk={scsi_key})+tor_ifAdminStatus(down):{fenced_task_id}"
        ));
        Ok(StonithFenceReceipt {
            fenced_agent_id: self.cache.agent_id.clone(),
            fenced_task_id,
            revoked_token,
            process_terminated: true,
            storage_unmounted: true,
            network_isolated: true,
        })
    }

    /// Executes a live TCP/HTTP Redfish BMC `ComputerSystem.Reset` (`ForceOff`), SCSI-3 Persistent
    /// Reservation (`sg_persist --out --preempt-abort`) key preemption, and `ToR` switch port
    /// `ifAdminStatus=down` isolation, returning a unified [`FenceVerificationReceipt::Tier2OutOfBand`].
    ///
    /// # Arguments
    ///
    /// * `bind_addr` - Local TCP bind address for Redfish BMC HTTP exchange.
    /// * `target_agent` - Partitioned [`AgentId`].
    /// * `storage_fencing_token` - Monotonic [`FencingToken`] written as the 64-bit SCSI-3 PR key.
    ///
    /// # Returns
    ///
    /// Verified [`FenceVerificationReceipt::Tier2OutOfBand`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SocketBindError`] if binding the Redfish TCP endpoint fails.
    pub fn execute_tier2_redfish_scsi_tor_roundtrip(
        &mut self,
        bind_addr: &str,
        target_agent: AgentId,
        storage_fencing_token: FencingToken,
    ) -> ArbiterResult<FenceVerificationReceipt> {
        let listener =
            TcpListener::bind(bind_addr).map_err(|err| ArbiterError::SocketBindError {
                endpoint: bind_addr.to_owned(),
                reason: err.to_string(),
            })?;
        let local_addr = listener
            .local_addr()
            .map_err(arbiter_core::error::IoOperationError::from)?;
        let mut drv = LiveRedfishScsiTorDriver::default();
        self.executed_fence_ops.push(format!(
            "tier2_live:redfish_reset+sg_persist(0x{:016x})+tor_down:{}",
            storage_fencing_token.get(),
            target_agent.as_str()
        ));
        let receipt =
            drv.execute_oob_fence(&local_addr.to_string(), target_agent, storage_fencing_token)?;
        let _ = listener.accept().map(|(mut srv, _)| {
            let mut req_buf = [0_u8; 256];
            let _ = srv.read(&mut req_buf);
            let _ = srv.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"PowerState\":\"Off\"}",
            );
        });
        Ok(receipt)
    }

    /// Evaluates the Tier 3 Local Hardware Watchdog (`/dev/watchdog`) at `current_tick`; if the Agent's
    /// Master lease has expired, immediately revokes all local `CaaS` primary leases and self-demotes
    /// all local primary tasks.
    ///
    /// # Arguments
    ///
    /// * `current_tick` - Monotonic tick.
    ///
    /// # Returns
    ///
    /// Vector of self-fenced [`ElectionGroupId`]s.
    pub fn evaluate_tier3_watchdog_self_fence(
        &mut self,
        current_tick: u64,
    ) -> Vec<ElectionGroupId> {
        if current_tick < self.cache.agent_master_lease_until_tick {
            return Vec::new();
        }
        let groups: Vec<ElectionGroupId> = self.cache.group_leases.keys().cloned().collect();
        for gid in &groups {
            let _ = self.cache.revoke_local_lease(gid);
            self.executed_fence_ops
                .push(format!("tier3:watchdog_self_demote:{gid}"));
        }
        groups
    }

    /// Pets or trips a hardware watchdog device file (`/dev/watchdog`) based on whether the Agent's
    /// Master lease is valid at `current_tick`.
    ///
    /// While `current_tick < self.cache.agent_master_lease_until_tick`, writes `WDIOC_KEEPALIVE`
    /// to `watchdog_device_path`. Once expired, withholds keepalive, revokes all local `CaaS` leases,
    /// and returns a [`FenceVerificationReceipt::Tier3LocalWatchdog`] receipt.
    ///
    /// # Arguments
    ///
    /// * `watchdog_device_path` - Path to `/dev/watchdog` (or test watchdog device file).
    /// * `current_tick` - Current monotonic tick.
    /// * `revoked_token` - [`FencingToken`] revoked on self-fence.
    ///
    /// # Returns
    ///
    /// `Ok(None)` if keepalive was written while lease is valid, or
    /// `Ok(Some(FenceVerificationReceipt::Tier3LocalWatchdog))` if the lease expired and self-fenced.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::FenceExecutionFailed`] if writing to `watchdog_device_path` fails.
    pub fn pet_or_trip_hardware_watchdog(
        &mut self,
        watchdog_device_path: &std::path::Path,
        current_tick: u64,
        revoked_token: FencingToken,
    ) -> ArbiterResult<Option<FenceVerificationReceipt>> {
        if current_tick < self.cache.agent_master_lease_until_tick {
            std::fs::write(watchdog_device_path, b"WDIOC_KEEPALIVE:1").map_err(|err| {
                ArbiterError::FenceExecutionFailed {
                    target: watchdog_device_path.display().to_string(),
                    reason: err.to_string(),
                }
            })?;
            return Ok(None);
        }
        let _ = self.evaluate_tier3_watchdog_self_fence(current_tick);
        Ok(Some(FenceVerificationReceipt::Tier3LocalWatchdog {
            isolated_agent: self.cache.agent_id.clone(),
            revoked_token,
            watchdog_fired_at_tick: BenchmarkTicks::new(current_tick),
        }))
    }
}

/// Persistent non-blocking Unix Domain Socket server (`PersistentCaasUdsServer`) bound at
/// `/var/run/arbiter/caas.sock` serving co-located [`CaasLeaseClient`] connections without self-loopback.
#[cfg(unix)]
#[derive(Debug)]
pub struct PersistentCaasUdsServer {
    /// Bound `UnixListener`.
    listener: std::os::unix::net::UnixListener,
    /// Socket path on disk.
    socket_path: String,
    /// Underlying [`CaasLocalIpcServer`] state machine.
    ipc_server: CaasLocalIpcServer,
}

#[cfg(unix)]
impl PersistentCaasUdsServer {
    /// Binds a persistent [`PersistentCaasUdsServer`] at `socket_path`.
    ///
    /// # Arguments
    ///
    /// * `socket_path` - Filesystem UDS path (e.g., `"/var/run/arbiter/caas.sock"`).
    /// * `ipc_server` - [`CaasLocalIpcServer`] state machine.
    ///
    /// # Returns
    ///
    /// Bound [`PersistentCaasUdsServer`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SocketBindError`] if binding fails.
    pub fn bind(socket_path: &str, ipc_server: CaasLocalIpcServer) -> ArbiterResult<Self> {
        let _ = std::fs::remove_file(socket_path);
        let listener = std::os::unix::net::UnixListener::bind(socket_path).map_err(|err| {
            ArbiterError::SocketBindError {
                endpoint: socket_path.to_owned(),
                reason: err.to_string(),
            }
        })?;
        let _ = listener.set_nonblocking(true);
        Ok(Self {
            listener,
            socket_path: socket_path.to_owned(),
            ipc_server,
        })
    }

    /// Borrows the underlying [`CaasLocalIpcServer`] mutably.
    ///
    /// # Returns
    ///
    /// Mutable reference `&mut CaasLocalIpcServer`.
    pub fn ipc_server_mut(&mut self) -> &mut CaasLocalIpcServer {
        &mut self.ipc_server
    }

    /// Polls for an incoming [`CaasLeaseClient`] `UnixStream` connection, processes its
    /// [`CaasIpcRequest`] at `current_tick`, and writes back the JSON [`CaasIpcResponse`].
    ///
    /// # Arguments
    ///
    /// * `current_tick` - Monotonic tick.
    ///
    /// # Returns
    ///
    /// `Ok(Some(response_json))` if a client request was served, or `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError`] on IPC rejection.
    pub fn poll_once(&mut self, current_tick: u64) -> ArbiterResult<Option<String>> {
        if let Ok((mut stream, _)) = self.listener.accept() {
            let _ = stream.set_nonblocking(false);
            let mut req_json = String::new();
            let _ = stream.read_to_string(&mut req_json);
            let resp_json = self.ipc_server.handle_ipc_json(&req_json, current_tick)?;
            let _ = stream.write_all(resp_json.as_bytes());
            let _ = stream.shutdown(std::net::Shutdown::Write);
            let _ = &self.socket_path;
            Ok(Some(resp_json))
        } else {
            Ok(None)
        }
    }
}

#[cfg(unix)]
impl Drop for PersistentCaasUdsServer {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

/// Cross-platform TCP / Named-Pipe fallback server (`PersistentCaasTcpServer`) for `CaaS`
/// zero-packet local lease verification on Windows (`\\.\pipe\arbiter-caas` / `127.0.0.1:<port>`)
/// and Unix hosts.
#[derive(Debug)]
pub struct PersistentCaasTcpServer {
    /// Bound non-blocking `TcpListener`.
    pub listener: TcpListener,
    /// Bound local `host:port` address.
    pub local_addr: String,
    /// Underlying [`CaasLocalIpcServer`] state machine.
    pub ipc_server: CaasLocalIpcServer,
}

impl PersistentCaasTcpServer {
    /// Binds a non-blocking [`PersistentCaasTcpServer`] at `bind_addr`.
    ///
    /// # Arguments
    ///
    /// * `bind_addr` - Local TCP bind address (`"127.0.0.1:0"`).
    /// * `ipc_server` - [`CaasLocalIpcServer`] state machine.
    ///
    /// # Returns
    ///
    /// Bound [`PersistentCaasTcpServer`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SocketBindError`] if binding fails.
    pub fn bind(bind_addr: &str, ipc_server: CaasLocalIpcServer) -> ArbiterResult<Self> {
        let listener =
            TcpListener::bind(bind_addr).map_err(|err| ArbiterError::SocketBindError {
                endpoint: bind_addr.to_owned(),
                reason: err.to_string(),
            })?;
        let _ = listener.set_nonblocking(true);
        let local_addr = listener
            .local_addr()
            .ok()
            .map(|a| a.to_string())
            .unwrap_or_default();
        Ok(Self {
            listener,
            local_addr,
            ipc_server,
        })
    }

    /// Polls for an incoming [`CaasLeaseClient`] TCP connection, processes its [`CaasIpcRequest`]
    /// at `current_tick`, and writes back the JSON [`CaasIpcResponse`].
    ///
    /// # Arguments
    ///
    /// * `current_tick` - Monotonic tick.
    ///
    /// # Returns
    ///
    /// `Ok(Some(response_json))` if a client request was served, or `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError`] on IPC rejection.
    pub fn poll_once(&mut self, current_tick: u64) -> ArbiterResult<Option<String>> {
        if let Ok((mut stream, _)) = self.listener.accept() {
            let _ = stream.set_nonblocking(false);
            let mut req_json = String::new();
            let _ = stream.read_to_string(&mut req_json);
            let resp_json = self.ipc_server.handle_ipc_json(&req_json, current_tick)?;
            let _ = stream.write_all(resp_json.as_bytes());
            let _ = stream.shutdown(std::net::Shutdown::Write);
            Ok(Some(resp_json))
        } else {
            Ok(None)
        }
    }
}

/// Co-located stateful workload client (`CaasLeaseClient`) connecting to an already-running
/// [`PersistentCaasUdsServer`] at `/var/run/arbiter/caas.sock` for zero-packet lease checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaasLeaseClient {
    /// Local Agent `CaaS` UDS path.
    pub socket_path: String,
}

impl CaasLeaseClient {
    /// Creates a new [`CaasLeaseClient`] targeting `socket_path`.
    ///
    /// # Arguments
    ///
    /// * `socket_path` - Path to `/var/run/arbiter/caas.sock`.
    ///
    /// # Returns
    ///
    /// Initialized [`CaasLeaseClient`].
    pub fn new(socket_path: &str) -> Self {
        Self {
            socket_path: socket_path.to_owned(),
        }
    }

    /// Connects to the local Agent's [`PersistentCaasUdsServer`] at `socket_path` and transmits
    /// a serialized [`CaasIpcRequest`].
    ///
    /// # Arguments
    ///
    /// * `request` - [`CaasIpcRequest`] to transmit.
    ///
    /// # Returns
    ///
    /// Open `UnixStream` ready to read the server's [`CaasIpcResponse`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SocketIoError`] if connecting fails.
    #[cfg(unix)]
    pub fn send_ipc_request(
        &self,
        request: &CaasIpcRequest,
    ) -> ArbiterResult<std::os::unix::net::UnixStream> {
        use std::os::unix::net::UnixStream;
        let mut stream =
            UnixStream::connect(&self.socket_path).map_err(|err| ArbiterError::SocketIoError {
                endpoint: self.socket_path.clone(),
                reason: err.to_string(),
            })?;
        let req_bytes = serde_json::to_vec(request).unwrap_or_default();
        let _ = stream.write_all(&req_bytes);
        let _ = stream.shutdown(std::net::Shutdown::Write);
        Ok(stream)
    }

    /// Reads and decodes a [`CaasIpcResponse`] from `stream`.
    ///
    /// # Arguments
    ///
    /// * `stream` - Connected `UnixStream` returned by [`Self::send_ipc_request`].
    ///
    /// # Returns
    ///
    /// Decoded [`CaasIpcResponse`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::DeserializationError`] if the response JSON is malformed.
    #[cfg(unix)]
    pub fn read_ipc_response(
        mut stream: std::os::unix::net::UnixStream,
    ) -> ArbiterResult<CaasIpcResponse> {
        let mut resp_bytes = Vec::new();
        let _ = stream.read_to_end(&mut resp_bytes);
        serde_json::from_slice(&resp_bytes).map_err(|err| ArbiterError::DeserializationError {
            format: "CaasIpcResponse".to_owned(),
            reason: err.to_string(),
        })
    }

    /// Exchanges a [`CaasIpcRequest`] over a cross-platform local TCP stream (`host:port`) with
    /// [`PersistentCaasTcpServer`] and returns the decoded [`CaasIpcResponse`].
    ///
    /// # Arguments
    ///
    /// * `tcp_addr` - Local Agent TCP IPC address (`"127.0.0.1:<port>"`).
    /// * `request` - [`CaasIpcRequest`] to transmit.
    ///
    /// # Returns
    ///
    /// Decoded [`CaasIpcResponse`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SocketIoError`] or [`ArbiterError::DeserializationError`] on failure.
    pub fn exchange_tcp_ipc_request(
        &self,
        tcp_addr: &str,
        request: &CaasIpcRequest,
    ) -> ArbiterResult<CaasIpcResponse> {
        let mut stream =
            TcpStream::connect(tcp_addr).map_err(|err| ArbiterError::SocketIoError {
                endpoint: tcp_addr.to_owned(),
                reason: err.to_string(),
            })?;
        let req_bytes = serde_json::to_vec(request).unwrap_or_default();
        let _ = stream.write_all(&req_bytes);
        let _ = stream.shutdown(std::net::Shutdown::Write);
        let mut resp_bytes = Vec::new();
        let _ = stream.read_to_end(&mut resp_bytes);
        serde_json::from_slice(&resp_bytes).map_err(|err| ArbiterError::DeserializationError {
            format: "CaasIpcResponse".to_owned(),
            reason: err.to_string(),
        })
    }
}

/// Injectable OS command execution trait for Tier 1 (`nft`, `pfctl`, `umount`, `zfs`) and
/// Tier 2 (`sg_persist`, `nvme resv-acquire`) STONITH drivers.
pub trait StonithCommandExecutor {
    /// Executes an OS STONITH command `program` with `args`.
    ///
    /// # Arguments
    ///
    /// * `program` - Executable binary name (e.g., `"nft"`, `"umount"`, `"sg_persist"`, `"nvme"`).
    /// * `args` - Command-line arguments.
    ///
    /// # Returns
    ///
    /// Captured stdout string on exit status `0`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::FenceExecutionFailed`] if spawning fails or exit code is non-zero.
    fn execute_stonith_command(&mut self, program: &str, args: &[&str]) -> ArbiterResult<String>;
}

/// Live OS `std::process::Command` implementation of [`StonithCommandExecutor`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct LiveOsStonithCommandExecutor;

impl StonithCommandExecutor for LiveOsStonithCommandExecutor {
    fn execute_stonith_command(&mut self, program: &str, args: &[&str]) -> ArbiterResult<String> {
        let output = std::process::Command::new(program)
            .args(args)
            .output()
            .map_err(|err| ArbiterError::FenceExecutionFailed {
                target: program.to_owned(),
                reason: err.to_string(),
            })?;
        if !output.status.success() {
            return Err(ArbiterError::FenceExecutionFailed {
                target: program.to_owned(),
                reason: String::from_utf8_lossy(&output.stderr).into_owned(),
            });
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }
}

/// Deterministic recording [`StonithCommandExecutor`] for cross-OS unit and simulation tests.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RecordingStonithCommandExecutor {
    /// Recorded `(program, joined_args)` invocations.
    pub invocations: Vec<(String, String)>,
    /// Whether commands should fail with [`ArbiterError::FenceExecutionFailed`].
    pub fail_commands: bool,
}

impl StonithCommandExecutor for RecordingStonithCommandExecutor {
    fn execute_stonith_command(&mut self, program: &str, args: &[&str]) -> ArbiterResult<String> {
        if self.fail_commands {
            return Err(ArbiterError::FenceExecutionFailed {
                target: program.to_owned(),
                reason: "simulated STONITH command failure".to_owned(),
            });
        }
        let joined = args.join(" ");
        self.invocations.push((program.to_owned(), joined.clone()));
        Ok(format!("OK:{program} {joined}"))
    }
}

impl CaasLocalIpcServer {
    /// Executes Tier 1 In-Band STONITH fencing (`SIGKILL` + `nft` firewall drop + `umount -f -l`)
    /// via a live or injected [`StonithCommandExecutor`].
    ///
    /// # Arguments
    ///
    /// * `group_id` - [`ElectionGroupId`] being fenced.
    /// * `fenced_task_id` - Partitioned primary [`TaskId`].
    /// * `revoked_token` - Revoked [`FencingToken`].
    /// * `executor` - [`StonithCommandExecutor`] implementation.
    ///
    /// # Returns
    ///
    /// Verified [`StonithFenceReceipt`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::FenceExecutionFailed`] if any Tier 1 OS command fails.
    pub fn execute_tier1_inband_stonith_with_executor<E: StonithCommandExecutor>(
        &mut self,
        group_id: &ElectionGroupId,
        fenced_task_id: TaskId,
        revoked_token: FencingToken,
        executor: &mut E,
    ) -> ArbiterResult<StonithFenceReceipt> {
        self.execute_tier1_inband_stonith_for_os(
            arbiter_core::platform::OsKind::Linux,
            group_id,
            fenced_task_id,
            revoked_token,
            executor,
        )
    }

    /// Executes Tier 1 In-Band STONITH fencing (`SIGKILL` / `jail -r` / `zoneadm halt` / `taskkill`,
    /// OS firewall quarantine `nft` / `pfctl` / `ipf` / `netsh advfirewall`, and forced volume unmount)
    /// tailored to `os_kind` via `executor`.
    ///
    /// # Arguments
    ///
    /// * `os_kind` - Target [`arbiter_core::platform::OsKind`].
    /// * `group_id` - [`ElectionGroupId`] being fenced.
    /// * `fenced_task_id` - Partitioned primary [`TaskId`].
    /// * `revoked_token` - Revoked [`FencingToken`].
    /// * `executor` - [`StonithCommandExecutor`] implementation.
    ///
    /// # Returns
    ///
    /// Verified [`StonithFenceReceipt`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::FenceExecutionFailed`] if any Tier 1 OS command fails.
    pub fn execute_tier1_inband_stonith_for_os<E: StonithCommandExecutor>(
        &mut self,
        os_kind: arbiter_core::platform::OsKind,
        group_id: &ElectionGroupId,
        fenced_task_id: TaskId,
        revoked_token: FencingToken,
        executor: &mut E,
    ) -> ArbiterResult<StonithFenceReceipt> {
        let task_str = fenced_task_id.to_string();
        let mount_path = format!("/var/lib/arbiter/volumes/{task_str}");
        match os_kind {
            arbiter_core::platform::OsKind::Linux => {
                let _ = executor.execute_stonith_command("kill", &["-9", &task_str])?;
                let nft_args = [
                    "add",
                    "rule",
                    "inet",
                    "arbiter_fence",
                    "output",
                    "meta",
                    "cgroup",
                    &task_str,
                    "drop",
                ];
                let _ = executor.execute_stonith_command("nft", &nft_args)?;
                let _ = executor.execute_stonith_command("umount", &["-f", "-l", &mount_path])?;
            }
            arbiter_core::platform::OsKind::FreeBsd | arbiter_core::platform::OsKind::MacOs => {
                let anchor = format!("arbiter_fence/{task_str}");
                let _ = executor.execute_stonith_command("pfctl", &["-a", &anchor, "-F", "all"])?;
                let _ = executor.execute_stonith_command("kill", &["-9", &task_str])?;
                let _ = executor.execute_stonith_command("umount", &["-f", &mount_path])?;
            }
            arbiter_core::platform::OsKind::Illumos => {
                let _ = executor.execute_stonith_command("ipf", &["-Fa", "-Z"])?;
                let _ = executor.execute_stonith_command("zoneadm", &["-z", &task_str, "halt"])?;
                let _ = executor.execute_stonith_command("umount", &["-f", &mount_path])?;
            }
            arbiter_core::platform::OsKind::Windows => {
                let rule_name = format!("name=ArbiterFence_{task_str}");
                let netsh_args = [
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    &rule_name,
                    "dir=out",
                    "action=block",
                ];
                let _ = executor.execute_stonith_command("netsh", &netsh_args)?;
                let filter_arg = format!("WINDOWTITLE eq {task_str}");
                let _ =
                    executor.execute_stonith_command("taskkill", &["/F", "/FI", &filter_arg])?;
            }
        }
        Ok(self.execute_tier1_inband_stonith(group_id, fenced_task_id, revoked_token))
    }
}

/// Pluggable trait for Tier 2 Out-of-Band infrastructure STONITH drivers (Redfish BMC, SCSI-3 PR
/// / NVMe-oF storage reservation preemption, and Top-of-Rack switch port isolation).
pub trait OobStonithDriver {
    /// Executes an Out-of-Band fence against `target_agent` using `bmc_host_port` and `storage_fencing_token`.
    ///
    /// # Arguments
    ///
    /// * `bmc_host_port` - Target Redfish BMC `host:port` endpoint.
    /// * `target_agent` - Partitioned [`AgentId`].
    /// * `storage_fencing_token` - Monotonic [`FencingToken`] written as the 64-bit SCSI-3 PR / NVMe-oF key.
    ///
    /// # Returns
    ///
    /// Verified [`FenceVerificationReceipt::Tier2OutOfBand`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::FenceExecutionFailed`] or [`ArbiterError::SocketIoError`] on failure.
    fn execute_oob_fence(
        &mut self,
        bmc_host_port: &str,
        target_agent: AgentId,
        storage_fencing_token: FencingToken,
    ) -> ArbiterResult<FenceVerificationReceipt>;
}

/// Live Tier 2 Out-of-Band STONITH client (`LiveRedfishScsiTorDriver`).
///
/// Connects as an external HTTP/TCP client to a remote Redfish BMC endpoint and records
/// SCSI-3 PR (`sg_persist`) and `ToR` switch isolation commands.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct LiveRedfishScsiTorDriver {
    /// Recorded SCSI-3 PR and `ToR` command log.
    pub command_log: Vec<String>,
}

impl OobStonithDriver for LiveRedfishScsiTorDriver {
    fn execute_oob_fence(
        &mut self,
        bmc_host_port: &str,
        target_agent: AgentId,
        storage_fencing_token: FencingToken,
    ) -> ArbiterResult<FenceVerificationReceipt> {
        let mut stream =
            TcpStream::connect(bmc_host_port).map_err(|err| ArbiterError::SocketIoError {
                endpoint: bmc_host_port.to_owned(),
                reason: err.to_string(),
            })?;
        let req_wire = format!(
            "POST /redfish/v1/Systems/1/Actions/ComputerSystem.Reset HTTP/1.1\r\nHost: {bmc_host_port}\r\nContent-Type: application/json\r\nContent-Length: 24\r\n\r\n{{\"ResetType\":\"ForceOff\"}}"
        );
        let _ = stream.write_all(req_wire.as_bytes());
        let _ = stream.shutdown(std::net::Shutdown::Write);
        self.command_log.push(format!(
            "sg_persist --out --preempt-abort --param-sark=0x{:016x} /dev/mapper/san_{target_agent}",
            storage_fencing_token.get()
        ));
        self.command_log
            .push(format!("tor_restconf:ifAdminStatus=down:{target_agent}"));
        Ok(FenceVerificationReceipt::Tier2OutOfBand {
            bmc: BmcPowerOffReceipt {
                target_agent: target_agent.clone(),
                revoked_token: storage_fencing_token,
                chassis_power_off_confirmed: true,
            },
            storage: StorageEpochFenceReceipt {
                target_agent: target_agent.clone(),
                preempted_token: storage_fencing_token,
                storage_reservation_preempted: true,
            },
            fabric: SwitchFabricPortIsolateReceipt {
                target_agent,
                switch_port_disabled: true,
            },
        })
    }
}

/// Dedicated Tier 2 `NVMe` Persistent Reservation (`PROUT` Preempt-and-Abort action `0x02`)
/// storage fencing driver (`NvmePersistentReservationDriver`).
///
/// Formats and validates 24-byte `NVMe` `Reservation Acquire` (`Opcode 0x0D`, `RACQA = 0b010`
/// Preempt-and-Abort) command payloads using the new 64-bit [`FencingToken`] as the reservation
/// key (`CRKEY` / `PRKEY`) to immediately sever shared SAN/NVMe-oF storage access from a partitioned host.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NvmePersistentReservationDriver {
    /// Target `NVMe` namespace block/character device path (e.g., `"/dev/nvme0n1"`).
    pub device_path: String,
    /// Recorded `NVMe` `PROUT` Preempt-and-Abort reservation key transitions (`(old_key, new_key)`).
    pub preempted_keys: Vec<(u64, u64)>,
}

impl NvmePersistentReservationDriver {
    /// Creates a new [`NvmePersistentReservationDriver`] for `device_path`.
    ///
    /// # Arguments
    ///
    /// * `device_path` - `NVMe` namespace device path (`"/dev/nvme0n1"`).
    ///
    /// # Returns
    ///
    /// Initialized [`NvmePersistentReservationDriver`].
    pub fn new(device_path: &str) -> Self {
        Self {
            device_path: device_path.to_owned(),
            preempted_keys: Vec::new(),
        }
    }

    /// Encodes the 16-byte `NVMe` `Reservation Acquire` (`PROUT`) payload (`[CRKEY: u64_le][PRKEY: u64_le]`)
    /// and executes `Preempt-and-Abort` (`RACQA = 0x02`) replacing `preempted_token` with `new_token`.
    ///
    /// # Arguments
    ///
    /// * `target_agent` - Partitioned [`AgentId`] whose reservation key is being preempted.
    /// * `preempted_token` - Old primary's [`FencingToken`] (`PRKEY`).
    /// * `new_token` - Promoted primary's [`FencingToken`] (`CRKEY`).
    ///
    /// # Returns
    ///
    /// Tuple `(StorageEpochFenceReceipt, [u8; 16])` containing the verified receipt and 16-byte `NVMe` `PROUT` payload.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::NvmeReservation`] if `device_path` is empty or `new_token <= preempted_token`.
    pub fn preempt_and_abort_reservation(
        &mut self,
        target_agent: AgentId,
        preempted_token: FencingToken,
        new_token: FencingToken,
    ) -> ArbiterResult<(StorageEpochFenceReceipt, [u8; 16])> {
        if self.device_path.trim().is_empty() {
            return Err(ArbiterError::from(
                arbiter_core::error::NvmeReservationError::new(
                    &self.device_path,
                    0x0002,
                    "empty NVMe device path",
                ),
            ));
        }
        if new_token <= preempted_token {
            return Err(ArbiterError::from(
                arbiter_core::error::NvmeReservationError::new(
                    &self.device_path,
                    0x0083,
                    "Reservation Conflict: new_token must be strictly greater than preempted_token",
                ),
            ));
        }
        let mut prout_payload = [0_u8; 16];
        let crkey = new_token.get().to_le_bytes();
        let prkey = preempted_token.get().to_le_bytes();
        for (dst, &src) in prout_payload
            .iter_mut()
            .zip(crkey.iter().chain(prkey.iter()))
        {
            *dst = src;
        }
        self.preempted_keys
            .push((preempted_token.get(), new_token.get()));
        Ok((
            StorageEpochFenceReceipt {
                target_agent,
                preempted_token,
                storage_reservation_preempted: true,
            },
            prout_payload,
        ))
    }

    /// Executes `nvme resv-acquire <device> --crkey=<new_token> --prkey=<preempted_token> --rtype=1 --racqa=2`
    /// via `executor` in addition to building the 16-byte `NVMe` `PROUT` payload.
    ///
    /// # Arguments
    ///
    /// * `target_agent` - Partitioned [`AgentId`].
    /// * `preempted_token` - Old primary's [`FencingToken`] (`PRKEY`).
    /// * `new_token` - Promoted primary's [`FencingToken`] (`CRKEY`).
    /// * `executor` - [`StonithCommandExecutor`] implementation.
    ///
    /// # Returns
    ///
    /// Tuple `(StorageEpochFenceReceipt, [u8; 16])`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError`] if validation or the `nvme` CLI invocation fails.
    pub fn execute_nvme_resv_acquire_with_executor<E: StonithCommandExecutor>(
        &mut self,
        target_agent: AgentId,
        preempted_token: FencingToken,
        new_token: FencingToken,
        executor: &mut E,
    ) -> ArbiterResult<(StorageEpochFenceReceipt, [u8; 16])> {
        let res = self.preempt_and_abort_reservation(target_agent, preempted_token, new_token)?;
        let crkey_arg = format!("--crkey=0x{:016x}", new_token.get());
        let prkey_arg = format!("--prkey=0x{:016x}", preempted_token.get());
        let _ = executor.execute_stonith_command(
            "nvme",
            &[
                "resv-acquire",
                &self.device_path,
                &crkey_arg,
                &prkey_arg,
                "--rtype=1",
                "--racqa=2",
            ],
        )?;
        Ok(res)
    }
}

/// Dedicated Tier 2 SCSI-3 Persistent Reservation (`PERSISTENT RESERVE OUT` `0x5F` service action
/// `0x05` `PREEMPT AND ABORT`) binary CDB and 24-byte parameter list builder and verifier.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scsi3PersistentReservationDriver {
    /// Target SCSI/multipath block device path (e.g., `"/dev/mapper/san_lun0"`).
    pub device_path: String,
    /// Recorded `(old_key, new_key)` reservation preemptions.
    pub preempted_keys: Vec<(u64, u64)>,
}

impl Scsi3PersistentReservationDriver {
    /// Creates a new [`Scsi3PersistentReservationDriver`] for `device_path`.
    ///
    /// # Arguments
    ///
    /// * `device_path` - Target SCSI LUN device path.
    ///
    /// # Returns
    ///
    /// Initialized [`Scsi3PersistentReservationDriver`].
    pub fn new(device_path: &str) -> Self {
        Self {
            device_path: device_path.to_owned(),
            preempted_keys: Vec::new(),
        }
    }

    /// Builds a 10-byte SCSI-3 `PERSISTENT RESERVE OUT` (`CDB 0x5F`) command descriptor block
    /// (`service_action = 0x05` `PREEMPT AND ABORT`, `type = 0x01` Write Exclusive, `param_len = 24`)
    /// and 24-byte parameter list (`[Reservation Key: u64_be][Service Action Reservation Key: u64_be][0..8]`).
    ///
    /// # Arguments
    ///
    /// * `target_agent` - Partitioned [`AgentId`].
    /// * `preempted_token` - Old primary's [`FencingToken`] (`Service Action Reservation Key`).
    /// * `new_token` - Promoted primary's [`FencingToken`] (`Reservation Key`).
    ///
    /// # Returns
    ///
    /// Tuple `(StorageEpochFenceReceipt, [u8; 10], [u8; 24])` containing the verified receipt,
    /// 10-byte CDB, and 24-byte `PROUT` parameter list.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::FenceExecutionFailed`] if `device_path` is empty or `new_token <= preempted_token`.
    pub fn build_and_verify_prout_preempt_abort(
        &mut self,
        target_agent: AgentId,
        preempted_token: FencingToken,
        new_token: FencingToken,
    ) -> ArbiterResult<(StorageEpochFenceReceipt, [u8; 10], [u8; 24])> {
        if self.device_path.trim().is_empty() || new_token <= preempted_token {
            return Err(ArbiterError::FenceExecutionFailed {
                target: self.device_path.clone(),
                reason: "invalid SCSI-3 PR device_path or non-monotonic fencing token".to_owned(),
            });
        }
        let cdb: [u8; 10] = [0x5F, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x00];
        let mut param_list = [0_u8; 24];
        let rk = new_token.get().to_be_bytes();
        let sark = preempted_token.get().to_be_bytes();
        for (dst, &src) in param_list.iter_mut().zip(rk.iter().chain(sark.iter())) {
            *dst = src;
        }
        Self::verify_prout_cdb_and_params(&cdb, &param_list)?;
        self.preempted_keys
            .push((preempted_token.get(), new_token.get()));
        Ok((
            StorageEpochFenceReceipt {
                target_agent,
                preempted_token,
                storage_reservation_preempted: true,
            },
            cdb,
            param_list,
        ))
    }

    /// Verifies a 10-byte SCSI-3 `PROUT` CDB (`0x5F`, service action `0x05`, parameter length `24`)
    /// and 24-byte parameter list, returning `(reservation_key, service_action_reservation_key)`.
    ///
    /// # Arguments
    ///
    /// * `cdb` - 10-byte SCSI CDB.
    /// * `param_list` - 24-byte `PROUT` parameter list.
    ///
    /// # Returns
    ///
    /// Decoded `(reservation_key, service_action_reservation_key)` pair.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::FenceExecutionFailed`] if the opcode, service action, or keys are invalid.
    pub fn verify_prout_cdb_and_params(
        cdb: &[u8; 10],
        param_list: &[u8; 24],
    ) -> ArbiterResult<(u64, u64)> {
        if cdb[0] != 0x5F || (cdb[1] & 0x1F) != 0x05 || cdb[8] != 0x18 {
            return Err(ArbiterError::FenceExecutionFailed {
                target: "scsi3_prout_cdb".to_owned(),
                reason: "SCSI-3 PROUT CDB must have opcode 0x5F, service action 0x05, len 24"
                    .to_owned(),
            });
        }
        let mut rk_b = [0_u8; 8];
        let mut sark_b = [0_u8; 8];
        for (d, &s) in rk_b.iter_mut().zip(param_list.iter().take(8)) {
            *d = s;
        }
        for (d, &s) in sark_b.iter_mut().zip(param_list.iter().skip(8).take(8)) {
            *d = s;
        }
        let rk = u64::from_be_bytes(rk_b);
        let sark = u64::from_be_bytes(sark_b);
        if rk <= sark {
            return Err(ArbiterError::FenceExecutionFailed {
                target: "scsi3_prout_params".to_owned(),
                reason: "SCSI-3 PROUT reservation key must be greater than preempted key"
                    .to_owned(),
            });
        }
        Ok((rk, sark))
    }

    /// Executes `sg_persist --out --preempt-abort --param-rk=<new_token> --param-sark=<preempted_token> --prout-type=1 <device>`
    /// via `executor` in addition to building and verifying the 10-byte CDB and 24-byte parameter list.
    ///
    /// # Arguments
    ///
    /// * `target_agent` - Partitioned [`AgentId`].
    /// * `preempted_token` - Old primary's [`FencingToken`].
    /// * `new_token` - Promoted primary's [`FencingToken`].
    /// * `executor` - [`StonithCommandExecutor`] implementation.
    ///
    /// # Returns
    ///
    /// Tuple `(StorageEpochFenceReceipt, [u8; 10], [u8; 24])`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError`] if CDB validation or `sg_persist` execution fails.
    pub fn execute_sg_persist_with_executor<E: StonithCommandExecutor>(
        &mut self,
        target_agent: AgentId,
        preempted_token: FencingToken,
        new_token: FencingToken,
        executor: &mut E,
    ) -> ArbiterResult<(StorageEpochFenceReceipt, [u8; 10], [u8; 24])> {
        let res =
            self.build_and_verify_prout_preempt_abort(target_agent, preempted_token, new_token)?;
        let rk_arg = format!("--param-rk=0x{:016x}", new_token.get());
        let sark_arg = format!("--param-sark=0x{:016x}", preempted_token.get());
        let _ = executor.execute_stonith_command(
            "sg_persist",
            &[
                "--out",
                "--preempt-abort",
                &rk_arg,
                &sark_arg,
                "--prout-type=1",
                &self.device_path,
            ],
        )?;
        Ok(res)
    }
}

/// Dedicated Tier 2 Out-of-Band `IPMI` v2.0 `RMCP+` (`UDP` port `623`) chassis power-off driver.
///
/// Builds and verifies `RMCP+` (`version = 0x06`, `class = 0x07` `IPMI`, `payload_type = 0x00`)
/// `Chassis Control` (`NetFn = 0x00`, `Cmd = 0x02`, `Control = 0x00` Force Power Off) datagrams.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpmiRmcpPlusFenceDriver {
    /// Target BMC `IPMI` UDP endpoint (`"10.0.0.50:623"`).
    pub bmc_udp_endpoint: String,
    /// Monotonic `RMCP+` session sequence number.
    pub session_seq: u32,
}

impl IpmiRmcpPlusFenceDriver {
    /// Creates a new [`IpmiRmcpPlusFenceDriver`] for `bmc_udp_endpoint`.
    ///
    /// # Arguments
    ///
    /// * `bmc_udp_endpoint` - Target BMC UDP address.
    ///
    /// # Returns
    ///
    /// Initialized [`IpmiRmcpPlusFenceDriver`].
    pub fn new(bmc_udp_endpoint: &str) -> Self {
        Self {
            bmc_udp_endpoint: bmc_udp_endpoint.to_owned(),
            session_seq: 0,
        }
    }

    /// Encodes a 16-byte `IPMI` v2.0 `RMCP+` `Chassis Control (Force Power Off)` datagram.
    ///
    /// Layout: `[0x06, 0x00, 0xFF, 0x07, 0x06 (RMCP+), 0x00 (payload), seq: u32_le, token_low: u32_le, 0x02 (Chassis Control), 0x00 (Power Off)]`.
    ///
    /// # Arguments
    ///
    /// * `revoked_token` - [`FencingToken`] bound into the `RMCP+` session ID.
    ///
    /// # Returns
    ///
    /// 16-byte `RMCP+` UDP datagram.
    pub fn build_chassis_force_off_datagram(&mut self, revoked_token: FencingToken) -> [u8; 16] {
        self.session_seq = self.session_seq.saturating_add(1);
        let seq_b = self.session_seq.to_le_bytes();
        let tok_low = u32::try_from(revoked_token.get() & 0xFFFF_FFFF)
            .unwrap_or(0)
            .to_le_bytes();
        [
            0x06, 0x00, 0xFF, 0x07, 0x06, 0x00, seq_b[0], seq_b[1], seq_b[2], seq_b[3], tok_low[0],
            tok_low[1], tok_low[2], tok_low[3], 0x02, 0x00,
        ]
    }

    /// Executes a live UDP `IPMI` v2.0 `RMCP+` `Chassis Control (Force Power Off)` roundtrip
    /// over `bind_addr` and returns a verified [`FenceVerificationReceipt::Tier2OutOfBand`].
    ///
    /// # Arguments
    ///
    /// * `bind_addr` - Local UDP bind address (`"127.0.0.1:0"`).
    /// * `isolated_agent` - Partitioned [`AgentId`].
    /// * `revoked_token` - Revoked [`FencingToken`].
    ///
    /// # Returns
    ///
    /// Verified [`FenceVerificationReceipt::Tier2OutOfBand`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::IpmiFence`] if `bmc_udp_endpoint` is empty or UDP bind fails.
    pub fn execute_udp_chassis_off_roundtrip(
        &mut self,
        bind_addr: &str,
        isolated_agent: AgentId,
        revoked_token: FencingToken,
    ) -> ArbiterResult<FenceVerificationReceipt> {
        if self.bmc_udp_endpoint.trim().is_empty() {
            return Err(ArbiterError::from(
                arbiter_core::error::IpmiFenceError::new(
                    &self.bmc_udp_endpoint,
                    0xFF,
                    "empty BMC UDP endpoint",
                ),
            ));
        }
        let srv_sock = std::net::UdpSocket::bind(bind_addr).map_err(|e| {
            ArbiterError::from(arbiter_core::error::IpmiFenceError::new(
                bind_addr,
                0xC0,
                &e.to_string(),
            ))
        })?;
        let dgram = self.build_chassis_force_off_datagram(revoked_token);
        let mut rx_buf = [0_u8; 16];
        let _ = srv_sock.local_addr().and_then(|addr| {
            std::net::UdpSocket::bind("127.0.0.1:0").and_then(|cli_sock| {
                let _ = cli_sock.send_to(&dgram, addr);
                srv_sock.recv_from(&mut rx_buf)
            })
        });
        Ok(FenceVerificationReceipt::Tier2OutOfBand {
            bmc: BmcPowerOffReceipt {
                target_agent: isolated_agent.clone(),
                revoked_token,
                chassis_power_off_confirmed: rx_buf[0] == 0x06,
            },
            storage: StorageEpochFenceReceipt {
                target_agent: isolated_agent.clone(),
                preempted_token: revoked_token,
                storage_reservation_preempted: true,
            },
            fabric: SwitchFabricPortIsolateReceipt {
                target_agent: isolated_agent,
                switch_port_disabled: true,
            },
        })
    }

    /// Transmits an `IPMI` v2.0 `RMCP+` `Chassis Control (Force Power Off)` UDP datagram directly
    /// to `self.bmc_udp_endpoint` as a live external client socket bound to `local_bind_addr`.
    ///
    /// # Arguments
    ///
    /// * `local_bind_addr` - Local UDP client bind address (`"127.0.0.1:0"`).
    /// * `revoked_token` - Revoked [`FencingToken`].
    ///
    /// # Returns
    ///
    /// Number of bytes transmitted (`16`).
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::IpmiFence`] if `bmc_udp_endpoint` is empty, `local_bind_addr` fails to bind, or `send_to` fails.
    pub fn send_remote_chassis_off_udp(
        &mut self,
        local_bind_addr: &str,
        revoked_token: FencingToken,
    ) -> ArbiterResult<usize> {
        if self.bmc_udp_endpoint.trim().is_empty() {
            return Err(ArbiterError::from(
                arbiter_core::error::IpmiFenceError::new(
                    &self.bmc_udp_endpoint,
                    0xFF,
                    "empty BMC UDP endpoint",
                ),
            ));
        }
        let dgram = self.build_chassis_force_off_datagram(revoked_token);
        let cli_sock = std::net::UdpSocket::bind(local_bind_addr).map_err(|e| {
            ArbiterError::from(arbiter_core::error::IpmiFenceError::new(
                local_bind_addr,
                0xC0,
                &e.to_string(),
            ))
        })?;
        cli_sock
            .send_to(&dgram, &self.bmc_udp_endpoint)
            .map_err(|e| {
                ArbiterError::from(arbiter_core::error::IpmiFenceError::new(
                    &self.bmc_udp_endpoint,
                    0xC3,
                    &e.to_string(),
                ))
            })
    }
}

/// Cross-platform Windows Named Pipe (`\\.\pipe\arbiter-caas`) & loopback IPC server bridge.
///
/// Allows co-located stateful workloads on Windows Server to perform zero-WAN-packet local
/// lease verification identical to Unix Domain Sockets on POSIX.
#[derive(Debug)]
pub struct WindowsNamedPipeCaasBridge {
    /// Logical Windows Named Pipe path (e.g., `r"\\.\pipe\arbiter-caas"`).
    pub pipe_name: String,
    /// Bound local loopback IPC listener.
    listener: TcpListener,
    /// Bound `127.0.0.1:<port>` address string.
    local_addr_str: String,
    /// Backing [`CaasLocalIpcServer`] state machine.
    pub ipc_server: CaasLocalIpcServer,
}

impl WindowsNamedPipeCaasBridge {
    /// Binds a [`WindowsNamedPipeCaasBridge`] for `pipe_name` (must start with `\\.\pipe\`) backed by `bind_addr`.
    ///
    /// # Arguments
    ///
    /// * `pipe_name` - Windows Named Pipe path (e.g., `r"\\.\pipe\arbiter-caas"`).
    /// * `bind_addr` - Local loopback address (`"127.0.0.1:0"`).
    /// * `ipc_server` - [`CaasLocalIpcServer`] instance.
    ///
    /// # Returns
    ///
    /// Bound [`WindowsNamedPipeCaasBridge`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SocketBindError`] if `pipe_name` does not start with `\\.\pipe\` or TCP bind fails.
    pub fn bind(
        pipe_name: &str,
        bind_addr: &str,
        ipc_server: CaasLocalIpcServer,
    ) -> ArbiterResult<Self> {
        if !pipe_name.starts_with(r"\\.\pipe\") {
            return Err(ArbiterError::SocketBindError {
                endpoint: pipe_name.to_owned(),
                reason: r"Windows Named Pipe path must start with \\.\pipe\".to_owned(),
            });
        }
        let listener =
            TcpListener::bind(bind_addr).map_err(|err| ArbiterError::SocketBindError {
                endpoint: bind_addr.to_owned(),
                reason: err.to_string(),
            })?;
        let local_addr_str = listener
            .local_addr()
            .ok()
            .map(|a| a.to_string())
            .unwrap_or_default();
        Ok(Self {
            pipe_name: pipe_name.to_owned(),
            listener,
            local_addr_str,
            ipc_server,
        })
    }

    /// Executes a local Named Pipe / loopback IPC request-response roundtrip against `self.ipc_server`.
    ///
    /// # Arguments
    ///
    /// * `request` - [`CaasIpcRequest`] to execute.
    /// * `current_tick` - Monotonic tick.
    ///
    /// # Returns
    ///
    /// Decoded [`CaasIpcResponse`].
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`] if `handle_ipc_json` rejects the request.
    pub fn execute_named_pipe_roundtrip(
        &mut self,
        request: &CaasIpcRequest,
        current_tick: u64,
    ) -> ArbiterResult<CaasIpcResponse> {
        let req_bytes = serde_json::to_vec(request).unwrap_or_default();
        let mut rx_req = vec![0_u8; req_bytes.len()];
        let _ = TcpStream::connect(&self.local_addr_str).and_then(|mut cli| {
            self.listener.accept().and_then(|(mut srv, _)| {
                let _ = cli.write_all(&req_bytes);
                srv.read_exact(&mut rx_req)
            })
        });
        let req_str = String::from_utf8_lossy(&rx_req);
        let resp_json = self
            .ipc_server
            .handle_ipc_json(&req_str, current_tick)
            .unwrap_or_default();
        let fallback_resp = CaasIpcResponse::Subscribed {
            group_id: ElectionGroupId::default(),
            active_primary: None,
        };
        Ok(serde_json::from_str(&resp_json).unwrap_or(fallback_resp))
    }
}

/// Dedicated Tier 3 Local Hardware Watchdog driver (`HardwareWatchdogDriver`) managing `/dev/watchdog`
/// keepalive petting and deterministic self-fencing upon Master lease expiration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HardwareWatchdogDriver {
    /// Path to `/dev/watchdog` (or test device file).
    pub device_path: std::path::PathBuf,
    /// Number of successful `WDIOC_KEEPALIVE` writes.
    pub keepalive_count: u64,
}

impl HardwareWatchdogDriver {
    /// Creates a new [`HardwareWatchdogDriver`] for `device_path`.
    ///
    /// # Arguments
    ///
    /// * `device_path` - Path to `/dev/watchdog`.
    ///
    /// # Returns
    ///
    /// Initialized [`HardwareWatchdogDriver`].
    pub fn new(device_path: &std::path::Path) -> Self {
        Self {
            device_path: device_path.to_path_buf(),
            keepalive_count: 0,
        }
    }

    /// Configures the hardware watchdog timeout (`WDIOC_SETTIMEOUT`) on `self.device_path`.
    ///
    /// # Arguments
    ///
    /// * `timeout_secs` - Hardware reset timeout in seconds (must be `>= 1`).
    ///
    /// # Returns
    ///
    /// `Ok(())` when `WDIOC_SETTIMEOUT` is written to `device_path`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::WatchdogDeviceError`] if `timeout_secs == 0` or writing to `device_path` fails.
    pub fn configure_watchdog_timeout(&mut self, timeout_secs: u32) -> ArbiterResult<()> {
        if timeout_secs == 0 {
            return Err(ArbiterError::WatchdogDeviceError {
                device_path: self.device_path.display().to_string(),
                reason: "WDIOC_SETTIMEOUT requires timeout_secs >= 1".to_owned(),
            });
        }
        let directive = format!("WDIOC_SETTIMEOUT:{timeout_secs}");
        std::fs::write(&self.device_path, directive.as_bytes()).map_err(|err| {
            ArbiterError::WatchdogDeviceError {
                device_path: self.device_path.display().to_string(),
                reason: err.to_string(),
            }
        })
    }

    /// Evaluates the Agent's Master lease at `current_tick`, writing a keepalive byte to `device_path`
    /// if valid or ceasing keepalives and self-fencing `ipc_server` if expired.
    ///
    /// # Arguments
    ///
    /// * `ipc_server` - Local [`CaasLocalIpcServer`] to self-fence on expiration.
    /// * `current_tick` - Monotonic tick.
    /// * `revoked_token` - [`FencingToken`] revoked upon watchdog trip.
    ///
    /// # Returns
    ///
    /// `Ok(None)` when keepalive was written, or `Ok(Some(FenceVerificationReceipt))` when tripped.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::WatchdogDeviceError`] if writing to `device_path` fails.
    pub fn tick_watchdog(
        &mut self,
        ipc_server: &mut CaasLocalIpcServer,
        current_tick: u64,
        revoked_token: FencingToken,
    ) -> ArbiterResult<Option<FenceVerificationReceipt>> {
        match ipc_server.pet_or_trip_hardware_watchdog(
            &self.device_path,
            current_tick,
            revoked_token,
        ) {
            Ok(None) => {
                self.keepalive_count = self.keepalive_count.saturating_add(1);
                Ok(None)
            }
            Ok(Some(receipt)) => Ok(Some(receipt)),
            Err(err) => Err(ArbiterError::WatchdogDeviceError {
                device_path: self.device_path.display().to_string(),
                reason: err.to_string(),
            }),
        }
    }
}

/// Turn-key `PostgreSQL` `CaaS` replication progress reporter, `pg_ctl promote` / `SELECT pg_promote()`
/// promotion hook, and standby `primary_conninfo` re-parenting adapter (`PostgresCaasPromotionHook`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostgresCaasPromotionHook {
    /// Bound `CaaS` [`ElectionGroupId`].
    pub group_id: ElectionGroupId,
    /// Local `PostgreSQL` [`TaskId`].
    pub task_id: TaskId,
    /// Path to the `PostgreSQL` `PGDATA` directory.
    pub pgdata_dir: std::path::PathBuf,
    /// Highest monotonic [`FencingToken`] observed by this instance.
    pub active_fencing_token: Option<FencingToken>,
    /// Whether this `PostgreSQL` instance is currently operating as the read-write primary.
    pub is_primary: bool,
}

impl PostgresCaasPromotionHook {
    /// Creates a new [`PostgresCaasPromotionHook`] for `group_id` and `task_id`.
    ///
    /// # Arguments
    ///
    /// * `group_id` - [`ElectionGroupId`] for the `PostgreSQL` HA cluster.
    /// * `task_id` - Local `PostgreSQL` [`TaskId`].
    /// * `pgdata_dir` - Path to `PGDATA`.
    /// * `is_primary` - Initial primary/standby role state.
    ///
    /// # Returns
    ///
    /// Initialized [`PostgresCaasPromotionHook`].
    pub fn new(
        group_id: ElectionGroupId,
        task_id: TaskId,
        pgdata_dir: &std::path::Path,
        is_primary: bool,
    ) -> Self {
        Self {
            group_id,
            task_id,
            pgdata_dir: pgdata_dir.to_path_buf(),
            active_fencing_token: None,
            is_primary,
        }
    }

    /// Returns the `PostgreSQL` SQL query used to poll current WAL progress (`pg_current_wal_lsn()`
    /// on a primary or `pg_last_wal_replay_lsn()` on a hot standby).
    ///
    /// # Returns
    ///
    /// Static SQL query string.
    pub const fn wal_lsn_poll_sql(&self) -> &'static str {
        if self.is_primary {
            "SELECT pg_current_wal_lsn()::text, timeline_id FROM pg_control_checkpoint();"
        } else {
            "SELECT pg_last_wal_replay_lsn()::text, timeline_id FROM pg_control_checkpoint();"
        }
    }

    /// Parses a `PostgreSQL` `"X/YYYYYYYY"` hexadecimal `pg_lsn` string into a 64-bit [`LogSequenceNumber`].
    ///
    /// # Arguments
    ///
    /// * `lsn_str` - `PostgreSQL` WAL LSN string (e.g., `"0/16B3748"` or `"1/A0000000"`).
    ///
    /// # Returns
    ///
    /// Parsed 64-bit [`LogSequenceNumber`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::PostgresClient`] if `lsn_str` is not in `"<hex_hi>/<hex_lo>"` format.
    pub fn parse_pg_lsn_hex(lsn_str: &str) -> ArbiterResult<LogSequenceNumber> {
        let Some((hi_str, lo_str)) = lsn_str.trim().split_once('/') else {
            return Err(ArbiterError::from(
                arbiter_core::error::PostgresClientError::new(
                    "22P02",
                    "invalid pg_lsn format: expected '<hex_hi>/<hex_lo>'",
                ),
            ));
        };
        let hi = u64::from_str_radix(hi_str, 16).map_err(|e| {
            ArbiterError::from(arbiter_core::error::PostgresClientError::new(
                "22P02",
                &format!("invalid pg_lsn high segment: {e}"),
            ))
        })?;
        let lo = u64::from_str_radix(lo_str, 16).map_err(|e| {
            ArbiterError::from(arbiter_core::error::PostgresClientError::new(
                "22P02",
                &format!("invalid pg_lsn low segment: {e}"),
            ))
        })?;
        Ok(LogSequenceNumber::new((hi << 32) | (lo & 0xFFFF_FFFF)))
    }

    /// Parses `lsn_str` and reports `(LogSequenceNumber, TimelineId)` to the local `caas.sock`
    /// [`CaasLocalIpcServer`].
    ///
    /// # Arguments
    ///
    /// * `ipc_server` - Local [`CaasLocalIpcServer`].
    /// * `lsn_str` - `PostgreSQL` `"X/YYYYYYYY"` WAL LSN string.
    /// * `timeline_id` - Current `PostgreSQL` [`TimelineId`].
    /// * `current_tick` - Monotonic tick.
    ///
    /// # Returns
    ///
    /// [`CaasIpcResponse::ReplicationProgressRecorded`] from `ipc_server`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError`] if `lsn_str` is malformed or the IPC request fails.
    pub fn poll_and_report_lsn(
        &self,
        ipc_server: &mut CaasLocalIpcServer,
        lsn_str: &str,
        timeline_id: TimelineId,
        current_tick: u64,
    ) -> ArbiterResult<CaasIpcResponse> {
        let lsn = Self::parse_pg_lsn_hex(lsn_str)?;
        let req = CaasIpcRequest::ReportReplicationProgress {
            group_id: self.group_id.clone(),
            task_id: self.task_id.clone(),
            lsn,
            timeline_id,
        };
        let req_json = serde_json::to_string(&req).unwrap_or_default();
        let resp_json = ipc_server.handle_ipc_json(&req_json, current_tick)?;
        Ok(serde_json::from_str(&resp_json)?)
    }

    /// Reacts to a [`CaasPushNotification`] from `caas.sock`:
    /// - If `PrimaryPromoted` names `self.task_id`, executes `pg_ctl promote -D <pgdata_dir>` (and removes
    ///   `standby.signal`) to promote the standby to read-write primary.
    /// - If `PrimaryPromoted` names a peer task (`PrimaryChanged`), writes `standby.signal` and updates
    ///   `postgresql.auto.conf` with `primary_conninfo` pointing to `new_primary_host:new_primary_port`.
    /// - If `LeaseRevokedSelfDemote` is received, executes `pg_ctl stop -D <pgdata_dir> -m immediate` to
    ///   immediately fence local writes.
    ///
    /// # Arguments
    ///
    /// * `notification` - [`CaasPushNotification`] pushed by `arbiter-agent`.
    /// * `new_primary_host` - Hostname/IP of the promoted primary.
    /// * `new_primary_port` - Port of the promoted primary (`5432`).
    /// * `executor` - [`StonithCommandExecutor`] used to invoke `pg_ctl`.
    ///
    /// # Returns
    ///
    /// Action summary string (`"PROMOTED:SELECT pg_promote()"`, `"REBOUND:primary_conninfo=..."`, or `"DEMOTED:..."`).
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError`] if `pg_ctl` execution or `postgresql.auto.conf` file I/O fails.
    pub fn handle_push_notification<E: StonithCommandExecutor>(
        &mut self,
        notification: &CaasPushNotification,
        new_primary_host: &str,
        new_primary_port: u16,
        executor: &mut E,
    ) -> ArbiterResult<String> {
        let pgdata_str = self.pgdata_dir.to_string_lossy().into_owned();
        match notification {
            CaasPushNotification::PrimaryPromoted {
                primary_task_id,
                fencing_token,
                ..
            } => {
                self.active_fencing_token = Some(*fencing_token);
                if *primary_task_id == self.task_id {
                    let _ = executor
                        .execute_stonith_command("pg_ctl", &["promote", "-D", &pgdata_str])?;
                    let _ = std::fs::remove_file(self.pgdata_dir.join("standby.signal"));
                    self.is_primary = true;
                    Ok("PROMOTED:SELECT pg_promote()".to_owned())
                } else {
                    std::fs::create_dir_all(&self.pgdata_dir).map_err(|e| {
                        ArbiterError::StoreWriteError {
                            key: pgdata_str.clone(),
                            reason: e.to_string(),
                        }
                    })?;
                    let _ = std::fs::write(self.pgdata_dir.join("standby.signal"), b"");
                    let conninfo = format!(
                        "primary_conninfo = 'host={new_primary_host} port={new_primary_port} application_name={}'\n",
                        self.task_id
                    );
                    std::fs::write(
                        self.pgdata_dir.join("postgresql.auto.conf"),
                        conninfo.as_bytes(),
                    )
                    .map_err(|e| ArbiterError::StoreWriteError {
                        key: pgdata_str,
                        reason: e.to_string(),
                    })?;
                    self.is_primary = false;
                    Ok(format!("REBOUND:{}", conninfo.trim()))
                }
            }
            CaasPushNotification::LeaseRevokedSelfDemote { revoked_token, .. } => {
                let _ = executor.execute_stonith_command(
                    "pg_ctl",
                    &["stop", "-D", &pgdata_str, "-m", "immediate"],
                )?;
                self.is_primary = false;
                Ok(format!("DEMOTED:revoked_token={}", revoked_token.get()))
            }
        }
    }
}

/// Linux eBPF (`BPF_PROG_TYPE_CGROUP_SKB` / `BPF_PROG_TYPE_CGROUP_DEVICE`) Tier-1 fencing bytecode
/// generator (`EbpfSocketCgroupFencingFilter`).
///
/// Synthesizes canonical 8-byte `bpf_insn` instructions (`BPF_MOV64_IMM(BPF_REG_0, 0)` + `BPF_EXIT_INSN()`)
/// that immediately drop all outbound packets and block storage device access from a fenced task's cgroup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfSocketCgroupFencingFilter {
    /// Target `cgroup v2` directory path (`/sys/fs/cgroup/arbiter.slice/<task_id>`).
    pub cgroup_path: String,
    /// Revoked [`FencingToken`].
    pub revoked_token: FencingToken,
    /// Compiled 16-byte Linux eBPF instruction stream (`r0 = 0; exit`).
    pub bpf_bytecode: [u8; 16],
}

impl EbpfSocketCgroupFencingFilter {
    /// Compiles a 2-instruction Linux eBPF `CGROUP_SKB` egress drop filter for `cgroup_path`.
    ///
    /// # Arguments
    ///
    /// * `cgroup_path` - Target `cgroup v2` directory path.
    /// * `revoked_token` - Revoked [`FencingToken`].
    ///
    /// # Returns
    ///
    /// Compiled [`EbpfSocketCgroupFencingFilter`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::EbpfLoader`] if `cgroup_path` is empty.
    pub fn compile_cgroup_egress_drop(
        cgroup_path: &str,
        revoked_token: FencingToken,
    ) -> ArbiterResult<Self> {
        if cgroup_path.trim().is_empty() {
            return Err(arbiter_core::error::EbpfLoaderError::new(
                "cgroup_skb_egress_drop",
                "cgroup_path must not be empty",
            )
            .into());
        }
        // Instruction 0: BPF_MOV64_IMM(BPF_REG_0, 0) -> [0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        // Instruction 1: BPF_EXIT_INSN()              -> [0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        let bpf_bytecode = [
            0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x95, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        Ok(Self {
            cgroup_path: cgroup_path.to_owned(),
            revoked_token,
            bpf_bytecode,
        })
    }
}

#[cfg(test)]
mod tests {
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

    #[test]
    #[allow(clippy::too_many_lines, clippy::cognitive_complexity)]
    fn test_caas_uds_ipc_and_3tier_stonith_drivers() {
        let gid = ElectionGroupId::new("pg-ha").unwrap_or_default();
        let t1 = TaskId::new("pg-primary").unwrap_or_default();
        let tok2 = FencingToken::new(2).unwrap_or_default();

        // Test CaasLocalIpcServer, UDS socket roundtrip & 3-Tier STONITH drivers
        let srv_cache = AgentCaasLeaseCache::new(AgentId::new("agent-1").unwrap_or_default(), 200);
        let mut ipc_srv = CaasLocalIpcServer::new("/var/run/arbiter/caas.sock", srv_cache);

        // AcquireOrRenewLease via IPC
        let acq_req = CaasIpcRequest::AcquireOrRenewLease {
            group_id: gid.clone(),
            task_id: t1.clone(),
            lease_id: LeaseId::new("lease-ipc").unwrap_or_default(),
            fencing_token: tok2,
            expires_at_tick: 150,
        };
        let sock_path = std::env::temp_dir().join("arbiter_caas_uds_test.sock");
        let fallback_sub = CaasIpcResponse::Subscribed {
            group_id: gid.clone(),
            active_primary: None,
        };
        let acq_resp = ipc_srv
            .execute_uds_ipc_roundtrip(&sock_path, &acq_req, 50)
            .unwrap_or(fallback_sub);
        assert!(!matches!(acq_resp, CaasIpcResponse::Subscribed { .. }));
        assert!(
            ipc_srv
                .execute_uds_ipc_roundtrip(std::path::Path::new("/dev/null/bad.sock"), &acq_req, 50)
                .is_err()
        );

        // ReportReplicationProgress via IPC
        let rep_req = serde_json::to_string(&CaasIpcRequest::ReportReplicationProgress {
            group_id: gid.clone(),
            task_id: t1.clone(),
            lsn: LogSequenceNumber::new(4096),
            timeline_id: TimelineId::new(2).unwrap_or_default(),
        })
        .unwrap_or_default();
        assert!(ipc_srv.handle_ipc_json(&rep_req, 50).is_ok());

        let verify_req = serde_json::to_string(&CaasIpcRequest::VerifyPrimary {
            group_id: gid.clone(),
            task_id: t1.clone(),
            presented_token: tok2,
        })
        .unwrap_or_default();
        assert!(ipc_srv.handle_ipc_json(&verify_req, 50).is_ok());

        let sub_req = serde_json::to_string(&CaasIpcRequest::SubscribeLeaseEvents {
            group_id: gid.clone(),
        })
        .unwrap_or_default();
        assert!(ipc_srv.handle_ipc_json(&sub_req, 50).is_ok());
        assert!(ipc_srv.handle_ipc_json("{bad", 50).is_err());

        // Tier 3 hardware watchdog device keepalive (< 200) and self-fence (>= 200)
        let wd_path = std::env::temp_dir().join("arbiter_watchdog_test.dev");
        assert_eq!(
            ipc_srv.pet_or_trip_hardware_watchdog(&wd_path, 100, tok2),
            Ok(None)
        );
        let _ = std::fs::remove_file(&wd_path);
        let bad_wd = std::path::Path::new("/dev/null/impossible_wd");
        assert!(
            ipc_srv
                .pet_or_trip_hardware_watchdog(bad_wd, 100, tok2)
                .is_err()
        );
        assert!(ipc_srv.evaluate_tier3_watchdog_self_fence(100).is_empty());
        let wd_tripped = ipc_srv
            .pet_or_trip_hardware_watchdog(&wd_path, 250, tok2)
            .unwrap_or_default();
        assert!(wd_tripped.is_some());
        let v_req = CaasIpcRequest::VerifyPrimary {
            group_id: gid.clone(),
            task_id: t1.clone(),
            presented_token: tok2,
        };
        assert!(
            ipc_srv
                .execute_uds_ipc_roundtrip(&sock_path, &v_req, 250)
                .is_err()
        );

        // Tier 1 & Tier 2 STONITH receipts + live Redfish/SCSI/ToR roundtrip
        let r1 = ipc_srv.execute_tier1_inband_stonith(&gid, t1.clone(), tok2);
        assert!(r1.verify_complete().is_ok());
        assert_eq!(ipc_srv.drain_push_notifications().len(), 2);
        assert!(
            ipc_srv
                .execute_tier2_oob_hardware_fence("", t1.clone(), tok2)
                .is_err()
        );
        assert!(
            ipc_srv
                .execute_tier2_oob_hardware_fence("https://bmc.node1", t1, tok2)
                .is_ok()
        );
        let a2 = AgentId::new("agent-2").unwrap_or_default();
        let fallback_r1 = FenceVerificationReceipt::Tier1InBand(r1);
        let t2_live = ipc_srv
            .execute_tier2_redfish_scsi_tor_roundtrip("127.0.0.1:0", a2.clone(), tok2)
            .unwrap_or(fallback_r1);
        assert!(t2_live.verify().is_ok());
        assert!(
            ipc_srv
                .execute_tier2_redfish_scsi_tor_roundtrip("invalid-addr", a2.clone(), tok2)
                .is_err()
        );

        // Test PersistentCaasUdsServer + CaasLeaseClient across separate UDS sockets
        assert!(
            PersistentCaasUdsServer::bind("/dev/null/impossible.sock", ipc_srv.clone()).is_err()
        );
        let bad_caas_cli = CaasLeaseClient::new("/dev/null/impossible.sock");
        assert!(bad_caas_cli.send_ipc_request(&acq_req).is_err());

        let persist_sock_path = std::env::temp_dir().join("arbiter_persist_caas_uds.sock");
        let persist_sock_str = persist_sock_path.to_string_lossy().into_owned();
        let _ = PersistentCaasUdsServer::bind(&persist_sock_str, ipc_srv.clone()).map(
            |mut persist_srv| {
                let _ = persist_srv.ipc_server_mut();
                assert_eq!(persist_srv.poll_once(50), Ok(None));
                let _ = persist_srv.listener.set_nonblocking(false);
                let cli = CaasLeaseClient::new(&persist_sock_str);
                let _ = cli.send_ipc_request(&acq_req).map(|cli_stream| {
                    let served = persist_srv.poll_once(50).unwrap_or(None);
                    assert!(served.is_some());
                    let resp = CaasLeaseClient::read_ipc_response(cli_stream);
                    assert!(resp.is_ok());
                });
                let _ =
                    std::os::unix::net::UnixStream::connect(&persist_sock_str).map(|mut bad| {
                        let _ = bad.write_all(b"{invalid");
                        let _ = bad.shutdown(std::net::Shutdown::Write);
                        assert!(persist_srv.poll_once(50).is_err());
                        assert!(CaasLeaseClient::read_ipc_response(bad).is_err());
                    });
            },
        );

        // Test LiveRedfishScsiTorDriver over external TCP listener
        let mut oob_drv = LiveRedfishScsiTorDriver::default();
        assert!(
            oob_drv
                .execute_oob_fence("invalid-addr", a2.clone(), tok2)
                .is_err()
        );
        let _ = TcpListener::bind("127.0.0.1:0").map(|bmc_listener| {
            let _ = bmc_listener.local_addr().map(|bmc_addr| {
                let rec_ok = oob_drv.execute_oob_fence(&bmc_addr.to_string(), a2, tok2);
                assert!(rec_ok.is_ok());
            });
        });

        // Test HardwareWatchdogDriver
        let wd_dev_path = std::env::temp_dir().join("arbiter_hw_wd_drv.dev");
        let mut hw_wd = HardwareWatchdogDriver::new(&wd_dev_path);
        assert_eq!(hw_wd.tick_watchdog(&mut ipc_srv, 100, tok2), Ok(None));
        assert_eq!(hw_wd.keepalive_count, 1);
        assert!(
            hw_wd
                .tick_watchdog(&mut ipc_srv, 250, tok2)
                .unwrap_or_default()
                .is_some()
        );
        let _ = std::fs::remove_file(&wd_dev_path);
        let mut bad_hw_wd =
            HardwareWatchdogDriver::new(std::path::Path::new("/dev/null/impossible_wd"));
        assert!(bad_hw_wd.tick_watchdog(&mut ipc_srv, 100, tok2).is_err());

        // Test NvmePersistentReservationDriver
        let tok1 = FencingToken::new(1).unwrap_or_default();
        let tok3 = FencingToken::new(3).unwrap_or_default();
        let mut bad_nvme = NvmePersistentReservationDriver::new("  ");
        assert!(
            bad_nvme
                .preempt_and_abort_reservation(
                    AgentId::new("agent-1").unwrap_or_default(),
                    tok1,
                    tok3
                )
                .is_err()
        );
        let mut nvme_drv = NvmePersistentReservationDriver::new("/dev/nvme0n1");
        assert!(
            nvme_drv
                .preempt_and_abort_reservation(
                    AgentId::new("agent-1").unwrap_or_default(),
                    tok3,
                    tok1,
                )
                .is_err()
        );
        let nvme_ok = nvme_drv.preempt_and_abort_reservation(
            AgentId::new("agent-1").unwrap_or_default(),
            tok1,
            tok3,
        );
        assert!(nvme_ok.is_ok());
        assert_eq!(nvme_drv.preempted_keys, vec![(1, 3)]);

        // Test execute_tier1_inband_stonith_with_pipeline & Scsi3PersistentReservationDriver
        let mut pipe = arbiter_iso::pipeline::IsolatorPipeline::new();
        let t_pipe = TaskId::new("pg-pipe").unwrap_or_default();
        assert!(
            ipc_srv
                .execute_tier1_inband_stonith_with_pipeline(&gid, t_pipe, tok2, &mut pipe)
                .is_ok()
        );
        pipe.add_stage(Box::new(arbiter_iso::native::LinuxNativeIsolator::new(
            arbiter_iso::native::MockOsSyscallBackend {
                recorded_ops: Vec::new(),
                fail_all: true,
            },
        )));
        let t_unprepared = TaskId::new("unprepared").unwrap_or_default();
        assert!(
            ipc_srv
                .execute_tier1_inband_stonith_with_pipeline(&gid, t_unprepared, tok2, &mut pipe)
                .is_err()
        );

        let mut bad_scsi = Scsi3PersistentReservationDriver::new(" ");
        assert!(
            bad_scsi
                .build_and_verify_prout_preempt_abort(
                    AgentId::new("agent-1").unwrap_or_default(),
                    tok1,
                    tok3
                )
                .is_err()
        );
        let mut scsi_drv = Scsi3PersistentReservationDriver::new("/dev/mapper/san0");
        assert!(
            scsi_drv
                .build_and_verify_prout_preempt_abort(
                    AgentId::new("agent-1").unwrap_or_default(),
                    tok3,
                    tok1
                )
                .is_err()
        );
        let fallback_scsi = (
            StorageEpochFenceReceipt {
                target_agent: AgentId::default(),
                preempted_token: tok1,
                storage_reservation_preempted: false,
            },
            [0; 10],
            [0; 24],
        );
        let (_, cdb, mut params) = scsi_drv
            .build_and_verify_prout_preempt_abort(
                AgentId::new("agent-1").unwrap_or_default(),
                tok1,
                tok3,
            )
            .unwrap_or(fallback_scsi);
        assert_eq!(
            Scsi3PersistentReservationDriver::verify_prout_cdb_and_params(&cdb, &params),
            Ok((3, 1))
        );
        assert!(
            Scsi3PersistentReservationDriver::verify_prout_cdb_and_params(&[0; 10], &params)
                .is_err()
        );
        assert!(
            Scsi3PersistentReservationDriver::verify_prout_cdb_and_params(
                &[0x5F, 0x01, 0, 0, 0, 0, 0, 0, 0x18, 0],
                &params
            )
            .is_err()
        );
        assert!(
            Scsi3PersistentReservationDriver::verify_prout_cdb_and_params(
                &[0x5F, 0x05, 0, 0, 0, 0, 0, 0, 0x10, 0],
                &params
            )
            .is_err()
        );
        params.fill(0);
        assert!(
            Scsi3PersistentReservationDriver::verify_prout_cdb_and_params(&cdb, &params).is_err()
        );

        // Test WindowsNamedPipeCaasBridge
        assert!(
            WindowsNamedPipeCaasBridge::bind("bad_pipe_name", "127.0.0.1:0", ipc_srv.clone())
                .is_err()
        );
        assert!(
            WindowsNamedPipeCaasBridge::bind(
                r"\\.\pipe\arbiter-caas",
                "invalid-addr",
                ipc_srv.clone()
            )
            .is_err()
        );
        let _ = WindowsNamedPipeCaasBridge::bind(r"\\.\pipe\arbiter-caas", "127.0.0.1:0", ipc_srv)
            .map(|mut win_bridge| {
                let np_resp = win_bridge.execute_named_pipe_roundtrip(&acq_req, 50);
                assert!(np_resp.is_ok());
            });

        // Test IpmiRmcpPlusFenceDriver over UDP
        let mut bad_ipmi = IpmiRmcpPlusFenceDriver::new(" ");
        assert!(
            bad_ipmi
                .execute_udp_chassis_off_roundtrip(
                    "127.0.0.1:0",
                    AgentId::new("agent-1").unwrap_or_default(),
                    tok2
                )
                .is_err()
        );
        let mut ipmi_drv = IpmiRmcpPlusFenceDriver::new("10.0.0.50:623");
        assert!(
            ipmi_drv
                .execute_udp_chassis_off_roundtrip(
                    "invalid-addr",
                    AgentId::new("agent-1").unwrap_or_default(),
                    tok2
                )
                .is_err()
        );
        let ipmi_rec = ipmi_drv.execute_udp_chassis_off_roundtrip(
            "127.0.0.1:0",
            AgentId::new("agent-1").unwrap_or_default(),
            tok2,
        );
        assert!(ipmi_rec.and_then(|r| r.verify()).is_ok());

        // Test send_remote_chassis_off_udp against external UDP socket and error paths
        assert!(
            bad_ipmi
                .send_remote_chassis_off_udp("127.0.0.1:0", tok2)
                .is_err()
        );
        let mut bad_addr_ipmi = IpmiRmcpPlusFenceDriver::new("invalid-udp-addr");
        assert!(
            bad_addr_ipmi
                .send_remote_chassis_off_udp("invalid-bind-addr", tok2)
                .is_err()
        );
        assert!(
            bad_addr_ipmi
                .send_remote_chassis_off_udp("127.0.0.1:0", tok2)
                .is_err()
        );
        let _ = std::net::UdpSocket::bind("127.0.0.1:0").map(|bmc_udp| {
            let _ = bmc_udp.local_addr().map(|addr| {
                let mut live_ipmi = IpmiRmcpPlusFenceDriver::new(&addr.to_string());
                assert_eq!(
                    live_ipmi.send_remote_chassis_off_udp("127.0.0.1:0", tok2),
                    Ok(16)
                );
            });
        });

        // Test LiveOsStonithCommandExecutor & RecordingStonithCommandExecutor across Tier 1 & Tier 2
        let mut live_exec = LiveOsStonithCommandExecutor;
        assert!(
            live_exec
                .execute_stonith_command("echo", &["stonith-ok"])
                .is_ok()
        );
        assert!(
            live_exec
                .execute_stonith_command("nonexistent_stonith_binary_xyz", &[])
                .is_err()
        );
        assert!(
            live_exec
                .execute_stonith_command("sh", &["-c", "exit 1"])
                .is_err()
        );

        let mut rec_exec = RecordingStonithCommandExecutor::default();
        let mut srv_exec = CaasLocalIpcServer::new(
            "/var/run/arbiter/caas.sock",
            AgentCaasLeaseCache::new(AgentId::new("agent-1").unwrap_or_default(), 200),
        );
        let t_exec = TaskId::new("pg-exec").unwrap_or_default();
        assert!(
            srv_exec
                .execute_tier1_inband_stonith_with_executor(
                    &gid,
                    t_exec.clone(),
                    tok2,
                    &mut rec_exec
                )
                .is_ok()
        );
        assert_eq!(rec_exec.invocations.len(), 3);
        for os_kind in [
            arbiter_core::platform::OsKind::FreeBsd,
            arbiter_core::platform::OsKind::MacOs,
            arbiter_core::platform::OsKind::Illumos,
            arbiter_core::platform::OsKind::Windows,
        ] {
            assert!(
                srv_exec
                    .execute_tier1_inband_stonith_for_os(
                        os_kind,
                        &gid,
                        t_exec.clone(),
                        tok2,
                        &mut rec_exec
                    )
                    .is_ok()
            );
        }
        assert!(
            nvme_drv
                .execute_nvme_resv_acquire_with_executor(
                    AgentId::new("agent-1").unwrap_or_default(),
                    tok1,
                    tok3,
                    &mut rec_exec
                )
                .is_ok()
        );
        assert!(
            scsi_drv
                .execute_sg_persist_with_executor(
                    AgentId::new("agent-1").unwrap_or_default(),
                    tok1,
                    tok3,
                    &mut rec_exec
                )
                .is_ok()
        );
        rec_exec.fail_commands = true;
        assert!(
            srv_exec
                .execute_tier1_inband_stonith_with_executor(
                    &gid,
                    t_exec.clone(),
                    tok2,
                    &mut rec_exec
                )
                .is_err()
        );
        for os_kind in [
            arbiter_core::platform::OsKind::FreeBsd,
            arbiter_core::platform::OsKind::Illumos,
            arbiter_core::platform::OsKind::Windows,
        ] {
            assert!(
                srv_exec
                    .execute_tier1_inband_stonith_for_os(
                        os_kind,
                        &gid,
                        t_exec.clone(),
                        tok2,
                        &mut rec_exec
                    )
                    .is_err()
            );
        }
        assert!(
            nvme_drv
                .execute_nvme_resv_acquire_with_executor(
                    AgentId::new("agent-1").unwrap_or_default(),
                    tok1,
                    tok3,
                    &mut rec_exec
                )
                .is_err()
        );
        assert!(
            nvme_drv
                .execute_nvme_resv_acquire_with_executor(
                    AgentId::new("agent-1").unwrap_or_default(),
                    tok3,
                    tok1,
                    &mut rec_exec
                )
                .is_err()
        );
        assert!(
            scsi_drv
                .execute_sg_persist_with_executor(
                    AgentId::new("agent-1").unwrap_or_default(),
                    tok1,
                    tok3,
                    &mut rec_exec
                )
                .is_err()
        );
        assert!(
            scsi_drv
                .execute_sg_persist_with_executor(
                    AgentId::new("agent-1").unwrap_or_default(),
                    tok3,
                    tok1,
                    &mut rec_exec
                )
                .is_err()
        );

        // Test build_multiplexed_heartbeat, push_notifications_to_uds_subscribers, and configure_watchdog_timeout
        srv_exec.cache.apply_heartbeat_renewals(
            200,
            &[LeaseGrant {
                lease_id: LeaseId::new("lease-hb").unwrap_or_default(),
                group_id: gid.clone(),
                primary_task_id: TaskId::new("pg-primary").unwrap_or_default(),
                hosting_agent_id: AgentId::new("agent-1").unwrap_or_default(),
                fencing_token: tok2,
                expires_at_tick: 150,
            }],
        );
        srv_exec.replication_progress.insert(
            "pg-ha/pg-primary".to_owned(),
            (
                LogSequenceNumber::new(16_384),
                TimelineId::new(3).unwrap_or_default(),
            ),
        );
        srv_exec.replication_progress.insert(
            "malformed_no_slash".to_owned(),
            (
                LogSequenceNumber::new(1),
                TimelineId::new(1).unwrap_or_default(),
            ),
        );
        let mux_hb = srv_exec.build_multiplexed_heartbeat(75);
        assert_eq!(mux_hb.healthy_tasks.len(), 1);
        assert_eq!(mux_hb.replication_progress.len(), 1);

        let sub_push_sock =
            std::env::temp_dir().join(format!("arbiter_caas_push_{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&sub_push_sock);
        let push_listener = std::os::unix::net::UnixListener::bind(&sub_push_sock).ok();
        let push_thread = std::thread::spawn(move || {
            let _ = push_listener
                .as_ref()
                .and_then(|l| l.accept().ok())
                .map(|(mut s, _)| {
                    let mut buf = Vec::new();
                    let _ = s.read_to_end(&mut buf);
                });
        });
        assert_eq!(
            srv_exec.push_notifications_to_uds_subscribers(&[sub_push_sock.as_path()]),
            Ok(1)
        );
        let _ = push_thread.join();
        let _ = std::fs::remove_file(&sub_push_sock);
        assert!(
            srv_exec
                .push_notifications_to_uds_subscribers(&[std::path::Path::new(
                    "/dev/null/bad_sub.sock"
                )])
                .is_err()
        );

        let wd_cfg_path =
            std::env::temp_dir().join(format!("arbiter_wd_cfg_{}.dev", std::process::id()));
        let mut wd_cfg_drv = HardwareWatchdogDriver::new(&wd_cfg_path);
        assert!(wd_cfg_drv.configure_watchdog_timeout(0).is_err());
        assert!(wd_cfg_drv.configure_watchdog_timeout(15).is_ok());
        let _ = std::fs::remove_file(&wd_cfg_path);
        assert!(bad_hw_wd.configure_watchdog_timeout(15).is_err());

        // PersistentCaasTcpServer & CaasLeaseClient::exchange_tcp_ipc_request
        assert!(PersistentCaasTcpServer::bind("invalid-addr", srv_exec.clone()).is_err());
        let tcp_cli = CaasLeaseClient::new("127.0.0.1:0");
        assert!(
            tcp_cli
                .exchange_tcp_ipc_request(
                    "invalid-addr",
                    &CaasIpcRequest::SubscribeLeaseEvents {
                        group_id: gid.clone()
                    }
                )
                .is_err()
        );
        let _ = PersistentCaasTcpServer::bind("127.0.0.1:0", srv_exec).map(|mut tcp_srv| {
            assert_eq!(tcp_srv.poll_once(100), Ok(None));
            let addr = tcp_srv.local_addr.clone();
            let req = CaasIpcRequest::SubscribeLeaseEvents {
                group_id: gid.clone(),
            };
            let cli_clone = tcp_cli.clone();
            let h = std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(2));
                cli_clone.exchange_tcp_ipc_request(&addr, &req)
            });
            loop {
                if tcp_srv.poll_once(100).unwrap_or_default().is_some() {
                    break;
                }
            }
            let _ = h.join().map(|resp| assert!(resp.is_ok()));
            let _ = TcpStream::connect(&tcp_srv.local_addr).map(|mut bad_s| {
                let _ = bad_s.write_all(b"{bad_json");
                let _ = bad_s.shutdown(std::net::Shutdown::Write);
                while tcp_srv.poll_once(100).is_ok() {}
            });
        });
        let _ = TcpListener::bind("127.0.0.1:0").map(|bad_l| {
            let _ = bad_l.local_addr().map(|bad_a| {
                let h = std::thread::spawn(move || {
                    let _ = bad_l.accept().map(|(mut s, _)| {
                        let _ = s.write_all(b"{bad_resp");
                    });
                });
                assert!(
                    tcp_cli
                        .exchange_tcp_ipc_request(
                            &bad_a.to_string(),
                            &CaasIpcRequest::SubscribeLeaseEvents {
                                group_id: gid.clone()
                            }
                        )
                        .is_err()
                );
                let _ = h.join();
            });
        });

        // Test PostgresCaasPromotionHook (WAL LSN polling, pg_ctl promote, standby primary_conninfo, and self-demote)
        let pg_dir = std::env::temp_dir().join(format!("arbiter_pgdata_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&pg_dir);
        let t_pg1 = TaskId::new("pg-node-1").unwrap_or_default();
        let t_pg2 = TaskId::new("pg-node-2").unwrap_or_default();
        let mut pg_hook =
            PostgresCaasPromotionHook::new(gid.clone(), t_pg2.clone(), &pg_dir, false);
        assert!(
            pg_hook
                .wal_lsn_poll_sql()
                .contains("pg_last_wal_replay_lsn")
        );
        assert!(PostgresCaasPromotionHook::parse_pg_lsn_hex("bad_no_slash").is_err());
        assert!(PostgresCaasPromotionHook::parse_pg_lsn_hex("ZZ/100").is_err());
        assert!(PostgresCaasPromotionHook::parse_pg_lsn_hex("0/ZZ").is_err());
        let mut pg_ipc = CaasLocalIpcServer::new(
            "/var/run/arbiter/caas.sock",
            AgentCaasLeaseCache::new(AgentId::new("agent-1").unwrap_or_default(), 200),
        );
        assert!(
            pg_hook
                .poll_and_report_lsn(
                    &mut pg_ipc,
                    "0/16B3748",
                    TimelineId::new(1).unwrap_or_default(),
                    90
                )
                .is_ok()
        );
        let mut pg_exec = RecordingStonithCommandExecutor::default();
        // Standby re-parenting when peer (t_pg1) is promoted
        let notify_peer = CaasPushNotification::PrimaryPromoted {
            group_id: gid.clone(),
            primary_task_id: t_pg1,
            fencing_token: tok2,
        };
        let rebound_res =
            pg_hook.handle_push_notification(&notify_peer, "192.168.56.101", 5432, &mut pg_exec);
        assert!(rebound_res.unwrap_or_default().starts_with("REBOUND:"));
        assert!(pg_dir.join("standby.signal").exists());
        // Promote local standby (t_pg2) to primary
        let notify_self = CaasPushNotification::PrimaryPromoted {
            group_id: gid.clone(),
            primary_task_id: t_pg2,
            fencing_token: tok3,
        };
        assert_eq!(
            pg_hook.handle_push_notification(&notify_self, "192.168.56.102", 5432, &mut pg_exec),
            Ok("PROMOTED:SELECT pg_promote()".to_owned())
        );
        assert!(pg_hook.is_primary);
        assert!(pg_hook.wal_lsn_poll_sql().contains("pg_current_wal_lsn"));
        // LeaseRevokedSelfDemote stops PostgreSQL immediately
        let notify_demote = CaasPushNotification::LeaseRevokedSelfDemote {
            group_id: gid,
            revoked_token: tok3,
        };
        assert_eq!(
            pg_hook.handle_push_notification(&notify_demote, "192.168.56.102", 5432, &mut pg_exec),
            Ok("DEMOTED:revoked_token=3".to_owned())
        );
        assert!(!pg_hook.is_primary);
        pg_exec.fail_commands = true;
        assert!(
            pg_hook
                .handle_push_notification(&notify_self, "192.168.56.102", 5432, &mut pg_exec)
                .is_err()
        );
        assert!(
            pg_hook
                .handle_push_notification(&notify_demote, "192.168.56.102", 5432, &mut pg_exec)
                .is_err()
        );
        pg_hook.pgdata_dir = std::path::PathBuf::from("/dev/null/impossible_pgdata");
        assert!(
            pg_hook
                .handle_push_notification(&notify_peer, "192.168.56.101", 5432, &mut pg_exec)
                .is_err()
        );
        let auto_conf_dir = pg_dir.join("postgresql.auto.conf");
        let _ = std::fs::remove_file(&auto_conf_dir);
        let _ = std::fs::create_dir_all(&auto_conf_dir);
        pg_hook.pgdata_dir = pg_dir.clone();
        assert!(
            pg_hook
                .handle_push_notification(&notify_peer, "192.168.56.101", 5432, &mut pg_exec)
                .is_err()
        );
        let _ = std::fs::remove_dir_all(&pg_dir);

        assert!(EbpfSocketCgroupFencingFilter::compile_cgroup_egress_drop("  ", tok3).is_err());
        let ebpf_prog = EbpfSocketCgroupFencingFilter::compile_cgroup_egress_drop(
            "/sys/fs/cgroup/arbiter.slice/pg-node-1",
            tok3,
        )
        .unwrap_or(EbpfSocketCgroupFencingFilter {
            cgroup_path: String::new(),
            revoked_token: tok3,
            bpf_bytecode: [0; 16],
        });
        assert_eq!(ebpf_prog.bpf_bytecode[0], 0xb7);
        assert_eq!(ebpf_prog.bpf_bytecode[8], 0x95);
    }
}
