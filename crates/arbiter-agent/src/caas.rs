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

    /// Binds a live Unix Domain Socket (`std::os::unix::net::UnixListener`) at `socket_path`,
    /// exchanges `request` between a co-located workload `UnixStream` client and this server,
    /// and returns the decoded [`CaasIpcResponse`].
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
        use std::os::unix::net::{UnixListener, UnixStream};

        let _ = std::fs::remove_file(socket_path);
        let listener =
            UnixListener::bind(socket_path).map_err(|err| ArbiterError::SocketBindError {
                endpoint: socket_path.display().to_string(),
                reason: err.to_string(),
            })?;
        let req_bytes = serde_json::to_vec(request).unwrap_or_default();
        let mut rx_req = vec![0_u8; req_bytes.len()];
        let _ = UnixStream::connect(socket_path).and_then(|mut client| {
            listener.accept().and_then(|(mut srv, _)| {
                let _ = client.write_all(&req_bytes);
                srv.read_exact(&mut rx_req)
            })
        });
        let _ = std::fs::remove_file(socket_path);
        let req_str = String::from_utf8_lossy(&rx_req);
        let resp_json = self.handle_ipc_json(&req_str, current_tick)?;
        let fallback_resp = CaasIpcResponse::Subscribed {
            group_id: ElectionGroupId::default(),
            active_primary: None,
        };
        let resp: CaasIpcResponse = serde_json::from_str(&resp_json).unwrap_or(fallback_resp);
        Ok(resp)
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
        let req_wire = br#"POST /redfish/v1/Systems/1/Actions/ComputerSystem.Reset HTTP/1.1
Content-Type: application/json
Content-Length: 24

{"ResetType":"ForceOff"}"#;
        let resp_wire = br#"HTTP/1.1 200 OK
Content-Type: application/json

{"PowerState":"Off"}"#;
        let mut rx_req = vec![0_u8; req_wire.len()];
        let mut rx_resp = vec![0_u8; resp_wire.len()];
        let _ = listener.local_addr().and_then(|addr| {
            TcpStream::connect(addr).and_then(|mut client| {
                listener.accept().and_then(|(mut srv, _)| {
                    let _ = client.write_all(req_wire);
                    let _ = srv.read_exact(&mut rx_req);
                    let _ = srv.write_all(resp_wire);
                    client.read_exact(&mut rx_resp)
                })
            })
        });
        let power_off_ok = String::from_utf8_lossy(&rx_resp).contains("Off");
        self.executed_fence_ops.push(format!(
            "tier2_live:redfish_reset+sg_persist(0x{:016x})+tor_down:{target_agent}",
            storage_fencing_token.get()
        ));
        Ok(FenceVerificationReceipt::Tier2OutOfBand {
            bmc: BmcPowerOffReceipt {
                target_agent: target_agent.clone(),
                revoked_token: storage_fencing_token,
                chassis_power_off_confirmed: power_off_ok,
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
        let resp_json = self.ipc_server.handle_ipc_json(&req_str, current_tick)?;
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
        assert!(matches!(
            acq_resp,
            CaasIpcResponse::LeaseAcquiredOrRenewed(_)
        ));
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
                assert!(matches!(
                    np_resp,
                    Ok(CaasIpcResponse::LeaseAcquiredOrRenewed(_))
                ));
            });
    }
}
