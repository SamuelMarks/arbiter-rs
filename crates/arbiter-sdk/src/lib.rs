//! Ergonomic, strongly-typed Rust Framework and Direct Job Client SDK for Arbiter (`arbiter-sdk`).
//!
//! Provides:
//! - [`FrameworkScheduler`] trait for implementing custom 2-level Mesos-style Frameworks (`on_offers_received`, `on_task_status_update`).
//! - [`FrameworkRunner`] for subscribing a [`FrameworkScheduler`] to a [`MasterNode`] and driving offer acceptance/decline cycles.
//! - [`ArbiterClient`] for submitting direct tasks, atomic gang jobs, and TPU/GPU topology workloads to a Master control plane.

#![forbid(missing_docs)]
#![forbid(clippy::missing_docs_in_private_items)]

use arbiter_core::error::{ArbiterError, ArbiterResult};
use arbiter_core::ids::{FrameworkId, OfferId, RoleName, TaskGroupId, TaskId};
use arbiter_core::resources::{GpuPartition, GpuVendor, ResourceBundle, TpuTopologySlice};
use arbiter_core::workload::{
    IsolationSpec, OfferFilter, OfferOperation, PreemptionPolicy, PriorityClass, ResourceOffer,
    TaskGroupSpec, TaskSpec, TopologyConstraint,
};
use arbiter_master::MasterNode;
use arbiter_net::http::{HttpGateway, HttpRequest};
use arbiter_net::quic::{FramedStreamTransport, QuicStreamKind};
use arbiter_net::security::SpiffeSvid;
use arbiter_proto::{
    AcceptOffers, SchedulerCall, SubmitDirectJob, SubscribeFramework, TaskStatusUpdate,
    WireEnvelope, WireMessage, encode_recordio_frame,
};
use arbiter_store::traits::StateStore;

/// Trait implemented by custom 2-level Mesos-style Frameworks consuming [`ResourceOffer`]s.
pub trait FrameworkScheduler {
    /// Returns the Framework's unique [`FrameworkId`].
    ///
    /// # Returns
    ///
    /// [`FrameworkId`].
    fn framework_id(&self) -> FrameworkId;

    /// Returns the [`RoleName`] under which this Framework subscribes.
    ///
    /// # Returns
    ///
    /// [`RoleName`].
    fn role(&self) -> RoleName;

    /// Returns the failover timeout in milliseconds for this Framework.
    ///
    /// # Returns
    ///
    /// Failover timeout in milliseconds.
    fn failover_timeout_ms(&self) -> u64;

    /// Invoked when the Master dispatches a batch of [`ResourceOffer`]s to this Framework.
    ///
    /// The Framework returns a vector of [`AcceptOffers`] responses (either launching tasks,
    /// reserving resources, or declining offers).
    ///
    /// # Arguments
    ///
    /// * `offers` - Slice of [`ResourceOffer`]s allocated to this Framework.
    ///
    /// # Returns
    ///
    /// Vector of [`AcceptOffers`] decisions.
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`] if the Framework scheduler encounters a domain error.
    fn on_offers_received(&mut self, offers: &[ResourceOffer]) -> ArbiterResult<Vec<AcceptOffers>>;

    /// Invoked when a task launched by this Framework transitions state on an Agent.
    ///
    /// # Arguments
    ///
    /// * `update` - [`TaskStatusUpdate`] notification.
    ///
    /// # Returns
    ///
    /// `Ok(())` on acknowledgement.
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`] if status handling fails.
    fn on_task_status_update(&mut self, update: &TaskStatusUpdate) -> ArbiterResult<()>;
}

/// Driver that connects a [`FrameworkScheduler`] implementation to a [`MasterNode`].
pub struct FrameworkRunner<F: FrameworkScheduler> {
    /// Underlying [`FrameworkScheduler`] implementation.
    pub scheduler: F,
    /// Whether the Framework has subscribed to the Master.
    pub is_subscribed: bool,
}

impl<F: FrameworkScheduler> FrameworkRunner<F> {
    /// Creates a new [`FrameworkRunner`] wrapping `scheduler`.
    ///
    /// # Arguments
    ///
    /// * `scheduler` - [`FrameworkScheduler`] implementation.
    ///
    /// # Returns
    ///
    /// Unsubscribed [`FrameworkRunner`].
    pub const fn new(scheduler: F) -> Self {
        Self {
            scheduler,
            is_subscribed: false,
        }
    }

    /// Subscribes the Framework with `master`.
    ///
    /// # Arguments
    ///
    /// * `master` - Target [`MasterNode`].
    ///
    /// # Returns
    ///
    /// `Ok(())` when subscribed.
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`] if the Framework's role does not exist on the Master.
    pub fn subscribe<S: StateStore>(&mut self, master: &mut MasterNode<S>) -> ArbiterResult<()> {
        master.subscribe_framework(SubscribeFramework {
            framework_id: self.scheduler.framework_id(),
            role: self.scheduler.role(),
            failover_timeout_ms: self.scheduler.failover_timeout_ms(),
        })?;
        self.is_subscribed = true;
        Ok(())
    }

    /// Dispatches all active offers belonging to this Framework from `master` to `scheduler.on_offers_received`
    /// and applies the resulting [`AcceptOffers`] operations back onto `master`.
    ///
    /// # Arguments
    ///
    /// * `master` - Target [`MasterNode`].
    /// * `current_tick` - Current monotonic tick.
    ///
    /// # Returns
    ///
    /// Number of [`AcceptOffers`] batches processed.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::FrameworkNotFound`] if not subscribed, or any error from the scheduler or Master.
    pub fn poll_and_process_offers<S: StateStore>(
        &mut self,
        master: &mut MasterNode<S>,
        current_tick: u64,
    ) -> ArbiterResult<usize> {
        if !self.is_subscribed {
            return Err(ArbiterError::FrameworkNotFound {
                framework_id: self.scheduler.framework_id().to_string(),
            });
        }

        let fw_id = self.scheduler.framework_id();
        let my_offers: Vec<ResourceOffer> = master
            .active_offers
            .values()
            .filter(|o| o.framework_id == fw_id)
            .cloned()
            .collect();

        if my_offers.is_empty() {
            return Ok(0);
        }

        let decisions = self.scheduler.on_offers_received(&my_offers)?;
        let count = decisions.len();
        for accept in &decisions {
            master.accept_offers(accept, current_tick)?;
        }
        Ok(count)
    }

    /// Delivers a [`TaskStatusUpdate`] to the wrapped [`FrameworkScheduler`].
    ///
    /// # Arguments
    ///
    /// * `update` - [`TaskStatusUpdate`] notification.
    ///
    /// # Returns
    ///
    /// `Ok(())` on acknowledgement.
    ///
    /// # Errors
    ///
    /// Propagates any [`ArbiterError`] from `scheduler.on_task_status_update`.
    pub fn deliver_status_update(&mut self, update: &TaskStatusUpdate) -> ArbiterResult<()> {
        self.scheduler.on_task_status_update(update)
    }

    /// Transmits a Mesos v1 [`SchedulerCall`] to `/api/v1/scheduler` over a live TCP HTTP/RecordIO
    /// connection via `gateway` and returns the `RecordIO`-framed response string.
    ///
    /// # Arguments
    ///
    /// * `gateway` - [`HttpGateway`] instance.
    /// * `bind_addr` - Local TCP bind address (`"127.0.0.1:0"`).
    /// * `client_svid` - Authenticated [`SpiffeSvid`] token.
    /// * `call` - [`SchedulerCall`] payload.
    /// * `seq` - Monotonic sequence number.
    /// * `current_tick` - Monotonic tick.
    ///
    /// # Returns
    ///
    /// `RecordIO`-encoded HTTP response frame (`"<len>\n<json>"`).
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SocketBindError`] or [`ArbiterError::AuthenticationFailed`] on failure.
    pub fn exchange_scheduler_call_over_http(
        &mut self,
        gateway: &HttpGateway,
        bind_addr: &str,
        client_svid: SpiffeSvid,
        call: SchedulerCall,
        seq: u64,
        current_tick: u64,
    ) -> ArbiterResult<String> {
        let env = WireEnvelope::new(seq, WireMessage::SchedulerCall(Box::new(call)));
        let req = HttpRequest {
            path: "/api/v1/scheduler".to_owned(),
            client_svid: Some(client_svid),
            body_json: env.to_json_string().unwrap_or_default(),
        };
        let (_, parsed_env, _) =
            gateway.execute_loopback_tcp_exchange(bind_addr, &req, current_tick)?;
        self.is_subscribed = true;
        Ok(encode_recordio_frame(&parsed_env))
    }
}

/// High-level client SDK for submitting direct tasks, gang jobs, and GPU/TPU topology workloads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArbiterClient {
    /// Default role used by this client when submitting workloads.
    pub default_role: RoleName,
}

impl ArbiterClient {
    /// Creates a new [`ArbiterClient`] bound to `default_role`.
    ///
    /// # Arguments
    ///
    /// * `default_role` - Default [`RoleName`] for submitted jobs.
    ///
    /// # Returns
    ///
    /// Initialized [`ArbiterClient`].
    pub const fn new(default_role: RoleName) -> Self {
        Self { default_role }
    }

    /// Submits a direct [`TaskSpec`] over a live/framed QUIC [`QuicStreamKind::Control`] transport.
    ///
    /// # Arguments
    ///
    /// * `transport` - [`FramedStreamTransport`] connected to the remote Master.
    /// * `task` - [`TaskSpec`] to transmit.
    /// * `seq` - Monotonic wire envelope sequence number.
    /// * `current_tick` - Monotonic tick.
    ///
    /// # Returns
    ///
    /// Submitted [`TaskId`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::QuicConnectionError`] if transmission fails.
    pub fn submit_task_over_quic<T: FramedStreamTransport>(
        &self,
        transport: &mut T,
        task: TaskSpec,
        seq: u64,
        current_tick: u64,
    ) -> ArbiterResult<TaskId> {
        let tid = task.task_id.clone();
        let env = WireEnvelope::new(
            seq,
            WireMessage::SubmitDirectJob(SubmitDirectJob::SingleTask(Box::new(task))),
        );
        transport.transmit_envelope(QuicStreamKind::Control, &env, current_tick)?;
        Ok(tid)
    }

    /// Submits a single direct [`TaskSpec`] to `master`.
    ///
    /// # Arguments
    ///
    /// * `master` - Target [`MasterNode`].
    /// * `task` - [`TaskSpec`] to enqueue.
    ///
    /// # Returns
    ///
    /// The submitted [`TaskId`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::RoleNotFound`] if `task.role` is not registered in `master`.
    pub fn submit_task<S: StateStore>(
        &self,
        master: &mut MasterNode<S>,
        task: TaskSpec,
    ) -> ArbiterResult<TaskId> {
        let _ = master.role_hierarchy.get_role(&task.role)?;
        let tid = task.task_id.clone();
        master.submit_direct_job(SubmitDirectJob::SingleTask(Box::new(task)));
        Ok(tid)
    }

    /// Builds and submits a GPU topology-aware direct task to `master`.
    ///
    /// # Arguments
    ///
    /// * `master` - Target [`MasterNode`].
    /// * `task_id` - Unique [`TaskId`].
    /// * `resources` - Requested [`ResourceBundle`].
    /// * `vendor` - Required [`GpuVendor`].
    /// * `partition` - Required [`GpuPartition`].
    /// * `constraints` - Hardware [`TopologyConstraint`]s (e.g., `NvLinkConnected`, `SameNuma`).
    /// * `command` - Executable command path.
    ///
    /// # Returns
    ///
    /// Submitted [`TaskId`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::RoleNotFound`] if `self.default_role` is unknown.
    #[allow(clippy::too_many_arguments)]
    pub fn submit_gpu_workload<S: StateStore>(
        &self,
        master: &mut MasterNode<S>,
        task_id: TaskId,
        resources: ResourceBundle,
        vendor: GpuVendor,
        partition: GpuPartition,
        constraints: Vec<TopologyConstraint>,
        command: &str,
    ) -> ArbiterResult<TaskId> {
        let spec = TaskSpec {
            task_id,
            role: self.default_role.clone(),
            framework_id: None,
            election_group: None,
            priority: PriorityClass::ProductionHigh,
            preemption_policy: PreemptionPolicy::CheckpointAndSuspend,
            resources,
            required_gpu_vendor: Some(vendor),
            required_gpu_partition: Some(partition),
            topology_constraints: constraints,
            isolation: IsolationSpec {
                capabilities: Vec::new(),
                image_ref: None,
                command: command.to_owned(),
                args: Vec::new(),
                env: Vec::new(),
                run_as_user: None,
            },
            artifacts: Vec::new(),
            secrets: Vec::new(),
            health_check: None,
        };
        self.submit_task(master, spec)
    }

    /// Submits an atomic multi-host gang job or TPU Pod slice workload to `master`.
    ///
    /// # Arguments
    ///
    /// * `master` - Target [`MasterNode`].
    /// * `group_id` - Unique [`TaskGroupId`].
    /// * `tasks` - Member [`TaskSpec`]s of the gang.
    /// * `tpu_slice` - Optional [`TpuTopologySlice`] torus requirement.
    /// * `placement_timeout_ms` - All-or-nothing placement timeout in milliseconds.
    ///
    /// # Returns
    ///
    /// Submitted [`TaskGroupId`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::InvalidResourceQuantity`] if `tasks` is empty, or
    /// [`ArbiterError::RoleNotFound`] if `self.default_role` is unknown.
    pub fn submit_gang_or_tpu_job<S: StateStore>(
        &self,
        master: &mut MasterNode<S>,
        group_id: TaskGroupId,
        tasks: Vec<TaskSpec>,
        tpu_slice: Option<TpuTopologySlice>,
        placement_timeout_ms: u64,
    ) -> ArbiterResult<TaskGroupId> {
        if tasks.is_empty() {
            return Err(ArbiterError::InvalidResourceQuantity {
                resource: "gang.tasks".to_owned(),
                quantity: 0,
                reason: "gang job must contain at least one member task".to_owned(),
            });
        }
        let _ = master.role_hierarchy.get_role(&self.default_role)?;
        master.submit_direct_job(SubmitDirectJob::GangJob(TaskGroupSpec {
            group_id: group_id.clone(),
            role: self.default_role.clone(),
            tasks,
            tpu_slice,
            placement_timeout_ms,
        }));
        Ok(group_id)
    }

    /// Helper to build a decline [`AcceptOffers`] response for a set of unwanted [`OfferId`]s.
    ///
    /// # Arguments
    ///
    /// * `framework_id` - [`FrameworkId`] declining the offers.
    /// * `offer_ids` - Vector of [`OfferId`]s to decline.
    /// * `refuse_milliseconds` - Duration to suppress offers from the agent.
    ///
    /// # Returns
    ///
    /// [`AcceptOffers`] containing a single `OfferOperation::Decline`.
    pub fn build_decline_offers(
        framework_id: FrameworkId,
        offer_ids: Vec<OfferId>,
        refuse_milliseconds: u64,
    ) -> AcceptOffers {
        AcceptOffers {
            framework_id,
            offer_ids,
            operations: vec![OfferOperation::Decline(OfferFilter {
                refuse_milliseconds,
                min_cpu_millicores: 0,
                min_memory_bytes: arbiter_core::units::Bytes::ZERO,
                min_gpu_vram: arbiter_core::units::Bytes::ZERO,
                refuse_gpu_offers: false,
            })],
        }
    }
}

/// Networked client SDK (`RemoteArbiterClient`) connecting to a remote `arbiter-master` over
/// QUIC (`arbiter-net::quic`) or HTTP/SSE (`arbiter-net::http`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteArbiterClient {
    /// Remote Master HTTP/REST endpoint (`"127.0.0.1:5051"`).
    pub master_http_endpoint: String,
    /// Remote Master QUIC endpoint (`"127.0.0.1:5050"`).
    pub master_quic_endpoint: String,
    /// Authenticated SPIFFE SVID for mTLS/HTTP requests.
    pub client_svid: SpiffeSvid,
    /// Default scheduling [`RoleName`].
    pub default_role: RoleName,
}

impl RemoteArbiterClient {
    /// Creates a new [`RemoteArbiterClient`].
    ///
    /// # Arguments
    ///
    /// * `master_http_endpoint` - Master HTTP/REST address.
    /// * `master_quic_endpoint` - Master QUIC address.
    /// * `client_svid` - Client [`SpiffeSvid`].
    /// * `default_role` - Default [`RoleName`].
    ///
    /// # Returns
    ///
    /// Initialized [`RemoteArbiterClient`].
    pub const fn new(
        master_http_endpoint: String,
        master_quic_endpoint: String,
        client_svid: SpiffeSvid,
        default_role: RoleName,
    ) -> Self {
        Self {
            master_http_endpoint,
            master_quic_endpoint,
            client_svid,
            default_role,
        }
    }

    /// Submits a [`SubmitDirectJob`] over HTTP `POST /api/v1/jobs` via `gateway`.
    ///
    /// # Arguments
    ///
    /// * `gateway` - [`HttpGateway`] instance.
    /// * `job` - [`SubmitDirectJob`] payload (`SingleTask` or `GangJob`).
    /// * `seq` - Monotonic sequence number.
    /// * `current_tick` - Monotonic tick.
    ///
    /// # Returns
    ///
    /// Returned [`WireEnvelope`] acknowledgement.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError`] if socket binding or authentication fails.
    pub fn submit_job_over_http(
        &self,
        gateway: &HttpGateway,
        job: SubmitDirectJob,
        seq: u64,
        current_tick: u64,
    ) -> ArbiterResult<WireEnvelope> {
        let env = WireEnvelope::new(seq, WireMessage::SubmitDirectJob(job));
        let req = HttpRequest {
            path: "/api/v1/jobs".to_owned(),
            client_svid: Some(self.client_svid.clone()),
            body_json: env.to_json_string().unwrap_or_default(),
        };
        let (_, resp_env, _) = gateway.execute_loopback_tcp_exchange(
            &self.master_http_endpoint,
            &req,
            current_tick,
        )?;
        Ok(resp_env)
    }

    /// Connects as an external TCP/HTTP client to a listening `arbiter-master` at
    /// `self.master_http_endpoint`, sends `envelope` to `path`, and decodes the response [`WireEnvelope`].
    ///
    /// # Arguments
    ///
    /// * `path` - Target HTTP API path (`"/api/v1/scheduler"`, `"/api/v1/jobs"`, `"/api/v1/operator"`).
    /// * `envelope` - Outbound [`WireEnvelope`].
    ///
    /// # Returns
    ///
    /// Decoded response [`WireEnvelope`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SocketIoError`] or [`ArbiterError::DeserializationError`] on failure.
    pub fn post_to_remote_master_http(
        &self,
        path: &str,
        envelope: &WireEnvelope,
    ) -> ArbiterResult<WireEnvelope> {
        use std::io::{Read, Write};

        let mut stream = std::net::TcpStream::connect(&self.master_http_endpoint).map_err(|e| {
            ArbiterError::SocketIoError {
                endpoint: self.master_http_endpoint.clone(),
                reason: e.to_string(),
            }
        })?;
        let body_json = envelope.to_json_string()?;
        let req_wire = format!(
            "POST {path} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body_json}",
            self.master_http_endpoint,
            body_json.len()
        );
        let _ = stream.write_all(req_wire.as_bytes());
        let _ = stream.shutdown(std::net::Shutdown::Write);
        let mut resp_bytes = Vec::new();
        let _ = stream.read_to_end(&mut resp_bytes);
        let resp_str = String::from_utf8_lossy(&resp_bytes);
        let body = resp_str
            .split_once("\r\n\r\n")
            .map_or(resp_str.as_ref(), |(_, b)| b);
        WireEnvelope::from_json_str(body.trim())
    }

    /// Sends `envelope` to `path` on `self.master_http_endpoint`, automatically following HTTP
    /// `307 Temporary Redirect` `Location` headers to the active Raft leader and retrying transient
    /// connection failures with exponential backoff.
    ///
    /// # Arguments
    ///
    /// * `path` - Target HTTP API path (`"/api/v1/scheduler"`, `"/api/v1/jobs"`, `"/api/v1/operator"`).
    /// * `envelope` - Outbound [`WireEnvelope`].
    /// * `max_retries` - Maximum retry attempts (`>= 1`).
    /// * `initial_backoff_ms` - Initial backoff delay in milliseconds (doubled on each retry).
    ///
    /// # Returns
    ///
    /// Decoded response [`WireEnvelope`] from the leader Master.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SocketIoError`] or [`ArbiterError::DeserializationError`] if all
    /// retry attempts fail.
    pub fn post_with_redirect_and_backoff(
        &mut self,
        path: &str,
        envelope: &WireEnvelope,
        max_retries: u32,
        initial_backoff_ms: u64,
    ) -> ArbiterResult<WireEnvelope> {
        use std::io::{Read, Write};

        let attempts = max_retries.max(1);
        let mut backoff_ms = initial_backoff_ms;
        let mut last_err = ArbiterError::SocketIoError {
            endpoint: self.master_http_endpoint.clone(),
            reason: "exhausted retries".to_owned(),
        };
        for _ in 0..attempts {
            match std::net::TcpStream::connect(&self.master_http_endpoint) {
                Ok(mut stream) => {
                    let body_json = envelope.to_json_string()?;
                    let req_wire = format!(
                        "POST {path} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body_json}",
                        self.master_http_endpoint,
                        body_json.len()
                    );
                    let _ = stream.write_all(req_wire.as_bytes());
                    let _ = stream.shutdown(std::net::Shutdown::Write);
                    let mut resp_bytes = Vec::new();
                    let _ = stream.read_to_end(&mut resp_bytes);
                    let resp_str = String::from_utf8_lossy(&resp_bytes);
                    if resp_str.starts_with("HTTP/1.1 307") {
                        for line in resp_str.lines() {
                            if let Some(loc) = line.strip_prefix("Location:") {
                                let trimmed = loc.trim().trim_start_matches("http://");
                                let host_port =
                                    trimmed.split('/').next().unwrap_or(trimmed).to_owned();
                                self.master_http_endpoint = host_port;
                            }
                        }
                        continue;
                    }
                    let body = resp_str
                        .split_once("\r\n\r\n")
                        .map_or(resp_str.as_ref(), |(_, b)| b);
                    return WireEnvelope::from_json_str(body.trim());
                }
                Err(err) => {
                    last_err = ArbiterError::SocketIoError {
                        endpoint: self.master_http_endpoint.clone(),
                        reason: err.to_string(),
                    };
                    std::thread::sleep(std::time::Duration::from_millis(backoff_ms));
                    backoff_ms = backoff_ms.saturating_mul(2);
                }
            }
        }
        Err(last_err)
    }
}

/// Zero-packet co-located `CaaS` client SDK (`CaasLeaseClient`) communicating with the local
/// `arbiter-agent` over Unix Domain Socket (`/var/run/arbiter/caas.sock`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaasLeaseClient {
    /// Path to the local Agent's `CaaS` Unix Domain Socket.
    pub uds_socket_path: String,
}

impl CaasLeaseClient {
    /// Creates a new [`CaasLeaseClient`] bound to `uds_socket_path`.
    ///
    /// # Arguments
    ///
    /// * `uds_socket_path` - Path to `/var/run/arbiter/caas.sock`.
    ///
    /// # Returns
    ///
    /// Initialized [`CaasLeaseClient`].
    pub const fn new(uds_socket_path: String) -> Self {
        Self { uds_socket_path }
    }

    /// Exchanges a JSON `CaasIpcRequest` over the local Unix Domain Socket (`self.uds_socket_path`)
    /// with `0` network packets.
    ///
    /// # Arguments
    ///
    /// * `request_json` - Serialized `CaasIpcRequest` JSON payload.
    ///
    /// # Returns
    ///
    /// Raw JSON response string from the local `arbiter-agent` `CaaS` server.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SocketIoError`] if connecting to `self.uds_socket_path` fails.
    pub fn exchange_uds_request(&self, request_json: &str) -> ArbiterResult<String> {
        use std::io::{Read, Write};

        #[cfg(unix)]
        let mut stream =
            std::os::unix::net::UnixStream::connect(&self.uds_socket_path).map_err(|e| {
                ArbiterError::SocketIoError {
                    endpoint: self.uds_socket_path.clone(),
                    reason: e.to_string(),
                }
            })?;
        #[cfg(not(unix))]
        let mut stream = {
            let addr_str = std::fs::read_to_string(&self.uds_socket_path).map_err(|e| {
                ArbiterError::SocketIoError {
                    endpoint: self.uds_socket_path.clone(),
                    reason: e.to_string(),
                }
            })?;
            std::net::TcpStream::connect(addr_str.trim()).map_err(|e| {
                ArbiterError::SocketIoError {
                    endpoint: self.uds_socket_path.clone(),
                    reason: e.to_string(),
                }
            })?
        };
        let _ = stream.write_all(request_json.as_bytes());
        let _ = stream.shutdown(std::net::Shutdown::Write);
        let mut resp = Vec::new();
        let _ = stream.read_to_end(&mut resp);
        Ok(String::from_utf8_lossy(&resp).into_owned())
    }
}

/// Networked 2-level Framework driver (`RemoteFrameworkDriver`) connecting a [`FrameworkScheduler`]
/// to a remote `arbiter-master` over QUIC or HTTP/RecordIO.
pub struct RemoteFrameworkDriver<F: FrameworkScheduler> {
    /// Wrapped [`FrameworkRunner`].
    pub runner: FrameworkRunner<F>,
    /// Remote [`RemoteArbiterClient`] transport configuration.
    pub client: RemoteArbiterClient,
}

impl<F: FrameworkScheduler> RemoteFrameworkDriver<F> {
    /// Creates a new [`RemoteFrameworkDriver`].
    ///
    /// # Arguments
    ///
    /// * `scheduler` - [`FrameworkScheduler`] implementation.
    /// * `client` - [`RemoteArbiterClient`] transport config.
    ///
    /// # Returns
    ///
    /// Initialized [`RemoteFrameworkDriver`].
    pub const fn new(scheduler: F, client: RemoteArbiterClient) -> Self {
        Self {
            runner: FrameworkRunner::new(scheduler),
            client,
        }
    }

    /// Subscribes the Framework over HTTP `POST /api/v1/scheduler` (`RecordIO` SSE) via `gateway`.
    ///
    /// # Arguments
    ///
    /// * `gateway` - [`HttpGateway`] instance.
    /// * `seq` - Sequence number.
    /// * `current_tick` - Monotonic tick.
    ///
    /// # Returns
    ///
    /// `RecordIO`-encoded `SUBSCRIBED` response frame.
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`] if the HTTP exchange fails.
    pub fn subscribe_over_http(
        &mut self,
        gateway: &HttpGateway,
        seq: u64,
        current_tick: u64,
    ) -> ArbiterResult<String> {
        let role = self.runner.scheduler.role();
        let call = SchedulerCall::Subscribe(
            SubscribeFramework {
                framework_id: self.runner.scheduler.framework_id(),
                role: role.clone(),
                failover_timeout_ms: self.runner.scheduler.failover_timeout_ms(),
            },
            arbiter_core::workload::CheckpointMode::Enabled,
            vec![role],
            Vec::new(),
        );
        self.runner.exchange_scheduler_call_over_http(
            gateway,
            &self.client.master_http_endpoint,
            self.client.client_svid.clone(),
            call,
            seq,
            current_tick,
        )
    }

    /// Processes a decoded [`arbiter_proto::SchedulerEvent`] received from a streaming `RecordIO`
    /// `/api/v1/scheduler` connection, invoking [`FrameworkScheduler`] callbacks and returning
    /// any follow-up [`SchedulerCall`]s (`Accept` or `Acknowledge`) to transmit back to the Master.
    ///
    /// # Arguments
    ///
    /// * `event` - Inbound [`arbiter_proto::SchedulerEvent`].
    ///
    /// # Returns
    ///
    /// Vector of outbound [`SchedulerCall`]s generated in response.
    ///
    /// # Errors
    ///
    /// Propagates any [`ArbiterError`] from `on_offers_received` or `on_task_status_update`.
    pub fn handle_scheduler_event(
        &mut self,
        event: arbiter_proto::SchedulerEvent,
    ) -> ArbiterResult<Vec<SchedulerCall>> {
        match event {
            arbiter_proto::SchedulerEvent::Subscribed(..) => {
                self.runner.is_subscribed = true;
                Ok(Vec::new())
            }
            arbiter_proto::SchedulerEvent::Offers(offers) => {
                let accepts = self.runner.scheduler.on_offers_received(&offers)?;
                Ok(accepts
                    .into_iter()
                    .map(|acc| SchedulerCall::Accept(acc, None, OfferFilter::default()))
                    .collect())
            }
            arbiter_proto::SchedulerEvent::Update(upd, uuid_opt) => {
                self.runner.scheduler.on_task_status_update(&upd)?;
                if let Some(uuid) = uuid_opt {
                    Ok(vec![SchedulerCall::Acknowledge(
                        self.runner.scheduler.framework_id(),
                        upd.agent_id,
                        upd.task_id,
                        uuid,
                    )])
                } else {
                    Ok(Vec::new())
                }
            }
            _ => Ok(Vec::new()),
        }
    }
}

/// Persistent streaming `RecordIO` runtime loop (`FrameworkRuntimeLoop`) driving a
/// [`RemoteFrameworkDriver`] against a live Master `/api/v1/scheduler` endpoint.
///
/// Tracks the negotiated `Mesos-Stream-Id` header, follows `HTTP/1.1 307 Temporary Redirect`
/// responses to the current Raft leader, decodes `RecordIO`-framed [`arbiter_proto::SchedulerEvent`]s,
/// and dispatches generated follow-up [`SchedulerCall`]s (`Accept`, `Acknowledge`).
pub struct FrameworkRuntimeLoop<F: FrameworkScheduler> {
    /// Underlying [`RemoteFrameworkDriver`].
    pub driver: RemoteFrameworkDriver<F>,
    /// Active `Mesos-Stream-Id` assigned by the Master upon `SUBSCRIBED`.
    pub active_stream_id: Option<String>,
    /// Incremental `RecordIO` stream decoder.
    pub recordio_decoder: arbiter_proto::RecordIoStreamDecoder,
}

impl<F: FrameworkScheduler> FrameworkRuntimeLoop<F> {
    /// Creates a new [`FrameworkRuntimeLoop`] wrapping `driver`.
    ///
    /// # Arguments
    ///
    /// * `driver` - [`RemoteFrameworkDriver`] instance.
    ///
    /// # Returns
    ///
    /// Initialized [`FrameworkRuntimeLoop`].
    pub const fn new(driver: RemoteFrameworkDriver<F>) -> Self {
        Self {
            driver,
            active_stream_id: None,
            recordio_decoder: arbiter_proto::RecordIoStreamDecoder::new(),
        }
    }

    /// Connects to `self.driver.client.master_http_endpoint` (following `307 Temporary Redirect`
    /// if the contacted node is a follower), sends `SchedulerCall::Subscribe`, extracts any
    /// `Mesos-Stream-Id` response header, decodes all `RecordIO` [`arbiter_proto::SchedulerEvent`]
    /// frames in the stream chunk, and returns the resulting outbound [`SchedulerCall`]s.
    ///
    /// # Arguments
    ///
    /// * `seq` - Monotonic wire sequence number.
    ///
    /// # Returns
    ///
    /// Vector of follow-up [`SchedulerCall`]s produced by the [`FrameworkScheduler`] callbacks.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError`] if TCP connection, `RecordIO` decoding, or a scheduler callback fails.
    pub fn connect_and_pump_recordio_once(
        &mut self,
        seq: u64,
    ) -> ArbiterResult<Vec<SchedulerCall>> {
        use std::io::{Read, Write};

        let role = self.driver.runner.scheduler.role();
        let sub_call = SchedulerCall::Subscribe(
            SubscribeFramework {
                framework_id: self.driver.runner.scheduler.framework_id(),
                role: role.clone(),
                failover_timeout_ms: self.driver.runner.scheduler.failover_timeout_ms(),
            },
            arbiter_core::workload::CheckpointMode::Enabled,
            vec![role],
            Vec::new(),
        );
        let sub_env = WireEnvelope::new(seq, WireMessage::SchedulerCall(Box::new(sub_call)));
        let recordio_req = encode_recordio_frame(&sub_env);

        for _ in 0..2 {
            let mut stream = std::net::TcpStream::connect(&self.driver.client.master_http_endpoint)
                .map_err(|e| ArbiterError::SocketIoError {
                    endpoint: self.driver.client.master_http_endpoint.clone(),
                    reason: e.to_string(),
                })?;
            let req_wire = format!(
                "POST /api/v1/scheduler HTTP/1.1\r\nHost: {}\r\nContent-Type: application/x-recordio\r\nAccept: application/x-recordio\r\nContent-Length: {}\r\n\r\n{recordio_req}",
                self.driver.client.master_http_endpoint,
                recordio_req.len()
            );
            let _ = stream.write_all(req_wire.as_bytes());
            let _ = stream.shutdown(std::net::Shutdown::Write);
            let mut resp_bytes = Vec::new();
            let _ = stream.read_to_end(&mut resp_bytes);
            let resp_str = String::from_utf8_lossy(&resp_bytes);
            if let Some(loc) = HttpGateway::extract_redirect_location(&resp_str) {
                let host_port = loc
                    .trim_start_matches("http://")
                    .split('/')
                    .next()
                    .unwrap_or(&loc)
                    .to_owned();
                self.driver.client.master_http_endpoint = host_port;
                continue;
            }
            let (headers, body) = resp_str.split_once("\r\n\r\n").unwrap_or(("", ""));
            for line in headers.lines() {
                if let Some(sid) = line
                    .strip_prefix("Mesos-Stream-Id:")
                    .or_else(|| line.strip_prefix("mesos-stream-id:"))
                {
                    self.active_stream_id = Some(sid.trim().to_owned());
                }
            }
            let envs = self.recordio_decoder.feed_chunk(body)?;
            let mut follow_ups = Vec::new();
            for env in envs {
                if let WireMessage::SchedulerEvent(ev_box) = env.message {
                    let calls = self.driver.handle_scheduler_event(*ev_box)?;
                    follow_ups.extend(calls);
                }
            }
            return Ok(follow_ups);
        }
        Err(ArbiterError::SocketIoError {
            endpoint: self.driver.client.master_http_endpoint.clone(),
            reason: "exceeded maximum leader redirect hops".to_owned(),
        })
    }
}

/// Returns the crate identifier for verification.
///
/// # Returns
///
/// The static crate name `"arbiter-sdk"`.
pub const fn crate_name() -> &'static str {
    "arbiter-sdk"
}

#[cfg(test)]
mod tests {
    use arbiter_alloc::drf::RoleAllocationState;
    use arbiter_core::ids::{AgentId, QuotaId};
    use arbiter_core::platform::{CpuArch, OsKind};
    use arbiter_core::topology::HardwareTopologyGraph;
    use arbiter_core::units::{Bytes, Millicores, WeightBasisPoints};
    use arbiter_core::workload::{Quota, Role, RoleHierarchy, TaskState};
    use arbiter_proto::RegisterAgent;
    use arbiter_store::memory::MemoryStateStore;

    use super::*;

    struct GreedyTestFramework {
        fw_id: FrameworkId,
        role: RoleName,
        launch_on_offer: bool,
        fail_on_offer: bool,
        observed_updates: usize,
    }

    impl FrameworkScheduler for GreedyTestFramework {
        fn framework_id(&self) -> FrameworkId {
            self.fw_id.clone()
        }

        fn role(&self) -> RoleName {
            self.role.clone()
        }

        fn failover_timeout_ms(&self) -> u64 {
            5000
        }

        fn on_offers_received(
            &mut self,
            offers: &[ResourceOffer],
        ) -> ArbiterResult<Vec<AcceptOffers>> {
            if self.fail_on_offer {
                return Err(ArbiterError::InvalidResourceQuantity {
                    resource: "simulated".to_owned(),
                    quantity: 0,
                    reason: "scheduler error".to_owned(),
                });
            }
            let mut out = Vec::new();
            for offer in offers {
                if self.launch_on_offer {
                    let task = TaskSpec {
                        task_id: TaskId::new("sdk-fw-task").unwrap_or_default(),
                        role: self.role.clone(),
                        framework_id: Some(self.fw_id.clone()),
                        election_group: None,
                        priority: PriorityClass::ProductionStandard,
                        preemption_policy: PreemptionPolicy::GracefulSigterm,
                        resources: ResourceBundle {
                            cpu: Millicores::new(1000),
                            memory: Bytes::new(1024),
                            ..ResourceBundle::zero()
                        },
                        required_gpu_vendor: None,
                        required_gpu_partition: None,
                        topology_constraints: Vec::new(),
                        isolation: IsolationSpec {
                            capabilities: Vec::new(),
                            image_ref: None,
                            command: "/bin/fw".to_owned(),
                            args: Vec::new(),
                            env: Vec::new(),
                            run_as_user: None,
                        },
                        artifacts: Vec::new(),
                        secrets: Vec::new(),
                        health_check: None,
                    };
                    out.push(AcceptOffers {
                        framework_id: self.fw_id.clone(),
                        offer_ids: vec![offer.offer_id.clone()],
                        operations: vec![OfferOperation::LaunchTask(Box::new(task))],
                    });
                } else {
                    out.push(ArbiterClient::build_decline_offers(
                        self.fw_id.clone(),
                        vec![offer.offer_id.clone()],
                        10,
                    ));
                }
            }
            Ok(out)
        }

        fn on_task_status_update(&mut self, _update: &TaskStatusUpdate) -> ArbiterResult<()> {
            self.observed_updates = self.observed_updates.saturating_add(1);
            Ok(())
        }
    }

    fn setup_master() -> (MasterNode<MemoryStateStore>, RoleName) {
        let role = RoleName::new("ml").unwrap_or_default();
        let mut h = RoleHierarchy::new();
        let _ = h.add_role(Role {
            name: role.clone(),
            parent: None,
            quota: Quota {
                id: QuotaId::new("q-ml").unwrap_or_default(),
                guaranteed_min: ResourceBundle::zero(),
                hard_max: ResourceBundle {
                    cpu: Millicores::new(100_000),
                    memory: Bytes::new(100_000_000),
                    ..ResourceBundle::zero()
                },
                allow_burst_borrowing: true,
                weight: WeightBasisPoints::STANDARD,
            },
        });
        let mut master = MasterNode::new(MemoryStateStore::new(), h, 100, 50);
        let _ = master.register_agent(
            RegisterAgent {
                agent_id: AgentId::new("agent-1").unwrap_or_default(),
                os_kind: OsKind::Linux,
                cpu_arch: CpuArch::X86_64,
                total_resources: ResourceBundle {
                    cpu: Millicores::new(16_000),
                    memory: Bytes::new(16_000_000),
                    ..ResourceBundle::zero()
                },
                topology: HardwareTopologyGraph::new(),
            },
            10,
        );
        (master, role)
    }

    #[test]
    fn test_sdk_framework_runner() {
        assert_eq!(crate_name(), "arbiter-sdk");
        let (mut master, role) = setup_master();

        let fw_id = FrameworkId::new("spark-fw").unwrap_or_default();
        let mut runner = FrameworkRunner::new(GreedyTestFramework {
            fw_id: fw_id.clone(),
            role: role.clone(),
            launch_on_offer: true,
            fail_on_offer: false,
            observed_updates: 0,
        });

        // Poll before subscribe -> Err
        assert!(runner.poll_and_process_offers(&mut master, 20).is_err());

        // Subscribe with bad role -> Err
        let mut bad_runner = FrameworkRunner::new(GreedyTestFramework {
            fw_id: fw_id.clone(),
            role: RoleName::new("ghost").unwrap_or_default(),
            launch_on_offer: true,
            fail_on_offer: false,
            observed_updates: 0,
        });
        assert!(bad_runner.subscribe(&mut master).is_err());

        // Subscribe valid
        assert!(runner.subscribe(&mut master).is_ok());

        // Poll when no offers exist -> Ok(0)
        assert_eq!(runner.poll_and_process_offers(&mut master, 20), Ok(0));

        // Generate offer via schedule_tick
        let states = vec![RoleAllocationState {
            role,
            framework_id: Some(fw_id),
            allocated: ResourceBundle::zero(),
            allocation_count: 0,
        }];
        let _ = master.schedule_tick(&states, 20);

        // Scheduler error propagation during offer callback
        runner.scheduler.fail_on_offer = true;
        assert!(runner.poll_and_process_offers(&mut master, 25).is_err());
        runner.scheduler.fail_on_offer = false;

        // Poll and launch task on offer
        assert_eq!(runner.poll_and_process_offers(&mut master, 25), Ok(1));

        // Generate another offer and test decline path + expired offer error path
        let _ = master.schedule_tick(&states, 30);
        runner.scheduler.launch_on_offer = false;
        assert_eq!(runner.poll_and_process_offers(&mut master, 35), Ok(1));

        let _ = master.schedule_tick(&states, 50);
        assert!(runner.poll_and_process_offers(&mut master, 500).is_err()); // expired at tick 500

        // Deliver status update
        assert!(
            runner
                .deliver_status_update(&TaskStatusUpdate {
                    task_id: TaskId::new("sdk-fw-task").unwrap_or_default(),
                    agent_id: AgentId::new("agent-1").unwrap_or_default(),
                    state: TaskState::Running,
                    message: "ok".to_owned(),
                })
                .is_ok()
        );
        assert_eq!(runner.scheduler.observed_updates, 1);

        // Live HTTP/RecordIO SchedulerCall exchange via FrameworkRunner
        let auth = arbiter_net::security::SvidAuthority::new("arbiter.internal", [9_u8; 32], 100);
        let svid = auth
            .issue_svid("spiffe://arbiter.internal/role/ml/task/fw", 10)
            .unwrap_or_default();
        let gw = HttpGateway::new(auth);
        let rio_resp = runner.exchange_scheduler_call_over_http(
            &gw,
            "127.0.0.1:0",
            svid.clone(),
            SchedulerCall::Revive(FrameworkId::new("spark-fw").unwrap_or_default(), Vec::new()),
            1,
            20,
        );
        assert!(rio_resp.is_ok());
        assert!(
            runner
                .exchange_scheduler_call_over_http(
                    &gw,
                    "invalid-addr",
                    svid,
                    SchedulerCall::Revive(
                        FrameworkId::new("spark-fw").unwrap_or_default(),
                        Vec::new(),
                    ),
                    2,
                    20,
                )
                .is_err()
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_sdk_client_quic_submission() {
        let (_, role) = setup_master();
        let client = ArbiterClient::new(role);
        let mut quic_conn =
            arbiter_net::quic::QuicMultiplexedConnection::new("127.0.0.1:5050", 2, 100, 1);
        let sample_t = TaskSpec {
            task_id: TaskId::new("quic-job-1").unwrap_or_default(),
            role: client.default_role.clone(),
            framework_id: None,
            election_group: None,
            priority: PriorityClass::Batch,
            preemption_policy: PreemptionPolicy::ImmediateKill,
            resources: ResourceBundle::zero(),
            required_gpu_vendor: None,
            required_gpu_partition: None,
            topology_constraints: Vec::new(),
            isolation: IsolationSpec {
                capabilities: Vec::new(),
                image_ref: None,
                command: "/bin/true".to_owned(),
                args: Vec::new(),
                env: Vec::new(),
                run_as_user: None,
            },
            artifacts: Vec::new(),
            secrets: Vec::new(),
            health_check: None,
        };
        assert!(
            client
                .submit_task_over_quic(&mut quic_conn, sample_t.clone(), 1, 2)
                .is_ok()
        );
        let mut zero_quic =
            arbiter_net::quic::QuicMultiplexedConnection::new("127.0.0.1:5050", 0, 100, 1);
        assert!(
            client
                .submit_task_over_quic(&mut zero_quic, sample_t.clone(), 2, 2)
                .is_err()
        );

        let auth = arbiter_net::security::SvidAuthority::new("arbiter.internal", [7_u8; 32], 100);
        let svid = auth
            .issue_svid("spiffe://arbiter.internal/role/ml/task/rem", 10)
            .unwrap_or_default();
        let gw = HttpGateway::new(auth);
        let rem_client = RemoteArbiterClient::new(
            "127.0.0.1:0".to_owned(),
            "127.0.0.1:5050".to_owned(),
            svid,
            client.default_role.clone(),
        );
        assert!(
            rem_client
                .submit_job_over_http(&gw, SubmitDirectJob::SingleTask(Box::new(sample_t)), 3, 20)
                .is_ok()
        );
        let mut rem_fw = RemoteFrameworkDriver::new(
            GreedyTestFramework {
                fw_id: FrameworkId::new("rem-fw").unwrap_or_default(),
                role: client.default_role.clone(),
                launch_on_offer: false,
                fail_on_offer: false,
                observed_updates: 0,
            },
            rem_client,
        );
        assert!(rem_fw.subscribe_over_http(&gw, 4, 20).is_ok());

        // Test handle_scheduler_event across Subscribed, Offers, Update, and Heartbeat
        assert_eq!(
            rem_fw.handle_scheduler_event(arbiter_proto::SchedulerEvent::Subscribed(
                FrameworkId::new("rem-fw").unwrap_or_default(),
                arbiter_core::workload::MasterInfo {
                    leader_id: "m1".to_owned(),
                    elected_term: 1,
                    version: "0.1.0".to_owned(),
                },
                arbiter_core::units::BenchmarkTicks::new(15),
            )),
            Ok(Vec::new())
        );
        let sample_offer = ResourceOffer {
            offer_id: OfferId::new("off-rem-1").unwrap_or_default(),
            framework_id: FrameworkId::new("rem-fw").unwrap_or_default(),
            agent_id: AgentId::new("agent-1").unwrap_or_default(),
            role: client.default_role.clone(),
            resources: ResourceBundle::zero(),
            revocable: false,
            expires_at_tick: 100,
        };
        assert_eq!(
            rem_fw
                .handle_scheduler_event(arbiter_proto::SchedulerEvent::Offers(vec![
                    sample_offer.clone()
                ]))
                .map(|v| v.len()),
            Ok(1)
        );
        rem_fw.runner.scheduler.fail_on_offer = true;
        assert!(
            rem_fw
                .handle_scheduler_event(arbiter_proto::SchedulerEvent::Offers(vec![sample_offer]))
                .is_err()
        );
        rem_fw.runner.scheduler.fail_on_offer = false;
        let sample_upd = TaskStatusUpdate {
            task_id: TaskId::new("t-rem-1").unwrap_or_default(),
            agent_id: AgentId::new("agent-1").unwrap_or_default(),
            state: TaskState::Running,
            message: "ok".to_owned(),
        };
        assert_eq!(
            rem_fw
                .handle_scheduler_event(arbiter_proto::SchedulerEvent::Update(
                    sample_upd.clone(),
                    Some(arbiter_core::ids::StatusUpdateUuid::new("u-rem-1").unwrap_or_default()),
                ))
                .map(|v| v.len()),
            Ok(1)
        );
        assert_eq!(
            rem_fw
                .handle_scheduler_event(arbiter_proto::SchedulerEvent::Update(sample_upd, None))
                .map(|v| v.len()),
            Ok(0)
        );
        assert_eq!(
            rem_fw.handle_scheduler_event(arbiter_proto::SchedulerEvent::Heartbeat),
            Ok(Vec::new())
        );

        // Test post_to_remote_master_http against a live TcpListener (both HTTP headers and raw body)
        for with_headers in [true, false] {
            let _ = std::net::TcpListener::bind("127.0.0.1:0").map(|listener| {
                let _ = listener.local_addr().map(|addr| {
                    let handle = std::thread::spawn(move || {
                        use std::io::{Read, Write};
                        let _ = listener.accept().map(|(mut srv, _)| {
                            let mut req = Vec::new();
                            let _ = srv.read_to_end(&mut req);
                            let ack_env = WireEnvelope::new(
                                99,
                                WireMessage::SchedulerEvent(Box::new(
                                    arbiter_proto::SchedulerEvent::Heartbeat,
                                )),
                            );
                            let body = ack_env.to_json_string().unwrap_or_default();
                            let wire = if with_headers {
                                format!(
                                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                                    body.len()
                                )
                            } else {
                                body
                            };
                            let _ = srv.write_all(wire.as_bytes());
                        });
                    });
                    let mut live_cli = rem_fw.client.clone();
                    live_cli.master_http_endpoint = addr.to_string();
                    let out_env = WireEnvelope::new(
                        98,
                        WireMessage::OperatorCall(Box::new(arbiter_proto::OperatorCall::GetHealth)),
                    );
                    assert!(
                        live_cli
                            .post_to_remote_master_http("/api/v1/operator", &out_env)
                            .is_ok()
                    );
                    let _ = handle.join();
                });
            });
        }

        rem_fw.client.master_http_endpoint = "invalid-addr".to_owned();
        assert!(
            rem_fw
                .client
                .post_to_remote_master_http(
                    "/api/v1/operator",
                    &WireEnvelope::new(
                        1,
                        WireMessage::OperatorCall(Box::new(arbiter_proto::OperatorCall::GetHealth)),
                    )
                )
                .is_err()
        );
        assert!(rem_fw.subscribe_over_http(&gw, 5, 20).is_err());
        assert!(
            rem_fw
                .client
                .submit_job_over_http(
                    &gw,
                    SubmitDirectJob::GangJob(TaskGroupSpec {
                        group_id: TaskGroupId::new("g1").unwrap_or_default(),
                        role: client.default_role,
                        tasks: Vec::new(),
                        tpu_slice: None,
                        placement_timeout_ms: 100,
                    }),
                    6,
                    20
                )
                .is_err()
        );
    }

    #[test]
    fn test_sdk_client_submissions() {
        let (mut master, role) = setup_master();

        // ArbiterClient direct task, GPU workload, and gang/TPU job submissions
        let client = ArbiterClient::new(role);
        let t_gpu = client.submit_gpu_workload(
            &mut master,
            TaskId::new("gpu-job-1").unwrap_or_default(),
            ResourceBundle {
                cpu: Millicores::new(4000),
                memory: Bytes::new(8192),
                ..ResourceBundle::zero()
            },
            GpuVendor::Nvidia,
            GpuPartition::WholeDevice,
            vec![TopologyConstraint::SameNuma],
            "/bin/cuda-train",
        );
        assert!(t_gpu.is_ok());

        // Gang job empty tasks -> Err
        let gid = TaskGroupId::new("tpu-gang-1").unwrap_or_default();
        assert!(
            client
                .submit_gang_or_tpu_job(&mut master, gid.clone(), Vec::new(), None, 1000)
                .is_err()
        );

        // Valid gang job
        let member = TaskSpec {
            task_id: TaskId::new("gang-member-1").unwrap_or_default(),
            role: client.default_role.clone(),
            framework_id: None,
            election_group: None,
            priority: PriorityClass::Batch,
            preemption_policy: PreemptionPolicy::ImmediateKill,
            resources: ResourceBundle::zero(),
            required_gpu_vendor: None,
            required_gpu_partition: None,
            topology_constraints: Vec::new(),
            isolation: IsolationSpec {
                capabilities: Vec::new(),
                image_ref: None,
                command: "/bin/true".to_owned(),
                args: Vec::new(),
                env: Vec::new(),
                run_as_user: None,
            },
            artifacts: Vec::new(),
            secrets: Vec::new(),
            health_check: None,
        };
        assert!(
            client
                .submit_gang_or_tpu_job(&mut master, gid.clone(), vec![member], None, 1000)
                .is_ok()
        );

        // Client with unknown role -> Err
        let bad_client = ArbiterClient::new(RoleName::new("unknown-role").unwrap_or_default());
        assert!(
            bad_client
                .submit_gpu_workload(
                    &mut master,
                    TaskId::new("gpu-bad").unwrap_or_default(),
                    ResourceBundle::zero(),
                    GpuVendor::Nvidia,
                    GpuPartition::WholeDevice,
                    Vec::new(),
                    "/bin/false",
                )
                .is_err()
        );
        let popped_tasks = master
            .pending_gang_jobs
            .pop()
            .map(|g| g.tasks)
            .unwrap_or_default();
        assert!(
            bad_client
                .submit_gang_or_tpu_job(&mut master, gid, popped_tasks, None, 1000)
                .is_err()
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_sdk_leader_redirect_backoff_and_caas_uds_client() {
        use std::io::{Read, Write};

        let (_, role) = setup_master();
        let auth = arbiter_net::security::SvidAuthority::new("arbiter.internal", [3_u8; 32], 100);
        let svid = auth
            .issue_svid("spiffe://arbiter.internal/role/ml/task/redir", 10)
            .unwrap_or_default();

        // 1. Follower listener returning HTTP/1.1 307 Temporary Redirect -> Leader listener returning 200 OK
        let leader_listener = std::net::TcpListener::bind("127.0.0.1:0").ok();
        let leader_addr = leader_listener
            .as_ref()
            .and_then(|l| l.local_addr().ok())
            .map(|a| a.to_string())
            .unwrap_or_default();
        let follower_listener = std::net::TcpListener::bind("127.0.0.1:0").ok();
        let follower_addr = follower_listener
            .as_ref()
            .and_then(|l| l.local_addr().ok())
            .map(|a| a.to_string())
            .unwrap_or_default();

        let leader_addr_clone = leader_addr.clone();
        let follower_thread = std::thread::spawn(move || {
            let _ = follower_listener
                .as_ref()
                .and_then(|l| l.accept().ok())
                .map(|(mut srv, _)| {
                    let mut req = Vec::new();
                    let _ = srv.read_to_end(&mut req);
                    let redir = format!(
                        "HTTP/1.1 307 Temporary Redirect\r\nLocation: http://{leader_addr_clone}/api/v1/operator\r\nContent-Length: 0\r\n\r\n"
                    );
                    let _ = srv.write_all(redir.as_bytes());
                });
        });
        let leader_thread = std::thread::spawn(move || {
            let _ = leader_listener
                .as_ref()
                .and_then(|l| l.accept().ok())
                .map(|(mut srv, _)| {
                    let mut req = Vec::new();
                    let _ = srv.read_to_end(&mut req);
                    let ack_env = WireEnvelope::new(
                        77,
                        WireMessage::SchedulerEvent(Box::new(
                            arbiter_proto::SchedulerEvent::Heartbeat,
                        )),
                    );
                    let body = ack_env.to_json_string().unwrap_or_default();
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = srv.write_all(resp.as_bytes());
                });
        });

        let mut cli =
            RemoteArbiterClient::new(follower_addr, "127.0.0.1:5050".to_owned(), svid, role);
        let req_env = WireEnvelope::new(
            76,
            WireMessage::OperatorCall(Box::new(arbiter_proto::OperatorCall::GetHealth)),
        );
        assert!(
            cli.post_with_redirect_and_backoff("/api/v1/operator", &req_env, 2, 0)
                .is_ok()
        );
        assert_eq!(cli.master_http_endpoint, leader_addr);
        let _ = follower_thread.join();
        let _ = leader_thread.join();

        // Backoff failure path (both initial_backoff_ms == 0 and > 0)
        "invalid-addr".clone_into(&mut cli.master_http_endpoint);
        assert!(
            cli.post_with_redirect_and_backoff("/api/v1/operator", &req_env, 2, 1)
                .is_err()
        );

        // 2. CaasLeaseClient over live Unix Domain Socket
        let uds_path =
            std::env::temp_dir().join(format!("arbiter_sdk_caas_{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&uds_path);
        #[cfg(unix)]
        let uds_listener = std::os::unix::net::UnixListener::bind(&uds_path).ok();
        #[cfg(not(unix))]
        let uds_listener = std::net::TcpListener::bind("127.0.0.1:0").ok().map(|tcp| {
            let addr_str = tcp
                .local_addr()
                .map(|a| a.to_string())
                .unwrap_or_else(|_| "127.0.0.1:0".to_owned());
            let _ = std::fs::write(&uds_path, addr_str.as_bytes());
            tcp
        });
        let uds_srv = std::thread::spawn(move || {
            let _ = uds_listener
                .as_ref()
                .and_then(|l| l.accept().ok())
                .map(|(mut s, _)| {
                    let mut rx = Vec::new();
                    let _ = s.read_to_end(&mut rx);
                    let _ = s.write_all(b"{\"status\":\"VerifyLeaseValid\"}");
                });
        });
        let caas_cli = CaasLeaseClient::new(uds_path.to_string_lossy().into_owned());
        assert_eq!(
            caas_cli.exchange_uds_request("{\"op\":\"VerifyLease\"}"),
            Ok("{\"status\":\"VerifyLeaseValid\"}".to_owned())
        );
        let _ = uds_srv.join();
        let _ = std::fs::remove_file(&uds_path);
        assert!(caas_cli.exchange_uds_request("{}").is_err());

        // 3. FrameworkRuntimeLoop (307 follower redirect -> leader RecordIO stream with Mesos-Stream-Id)
        let (_, role2) = setup_master();
        let auth2 = arbiter_net::security::SvidAuthority::new("arbiter.internal", [4_u8; 32], 100);
        let svid2 = auth2
            .issue_svid("spiffe://arbiter.internal/role/ml/task/rt", 10)
            .unwrap_or_default();
        let l_srv = std::net::TcpListener::bind("127.0.0.1:0").ok();
        let l_addr = l_srv
            .as_ref()
            .and_then(|l| l.local_addr().ok())
            .map(|a| a.to_string())
            .unwrap_or_default();
        let f_srv = std::net::TcpListener::bind("127.0.0.1:0").ok();
        let f_addr = f_srv
            .as_ref()
            .and_then(|l| l.local_addr().ok())
            .map(|a| a.to_string())
            .unwrap_or_default();
        let role2_clone = role2.clone();
        let f_handle = std::thread::spawn(move || {
            let _ = f_srv.as_ref().and_then(|l| l.accept().ok()).map(|(mut s, _)| {
                let mut rx = Vec::new();
                let _ = s.read_to_end(&mut rx);
                let redir = format!(
                    "HTTP/1.1 307 Temporary Redirect\r\nLocation: http://{l_addr}/api/v1/scheduler\r\nContent-Length: 0\r\n\r\n"
                );
                let _ = s.write_all(redir.as_bytes());
            });
        });
        let l_handle = std::thread::spawn(move || {
            let _ = l_srv.as_ref().and_then(|l| l.accept().ok()).map(|(mut s, _)| {
                let mut rx = Vec::new();
                let _ = s.read_to_end(&mut rx);
                let sub_ev = WireEnvelope::new(
                    1,
                    WireMessage::SchedulerEvent(Box::new(
                        arbiter_proto::SchedulerEvent::Subscribed(
                            FrameworkId::new("rt-fw").unwrap_or_default(),
                            arbiter_core::workload::MasterInfo {
                                leader_id: "m1".to_owned(),
                                elected_term: 1,
                                version: "0.1.0".to_owned(),
                            },
                            arbiter_core::units::BenchmarkTicks::new(15),
                        ),
                    )),
                );
                let off_ev = WireEnvelope::new(
                    2,
                    WireMessage::SchedulerEvent(Box::new(arbiter_proto::SchedulerEvent::Offers(
                        vec![ResourceOffer {
                            offer_id: OfferId::new("off-rt-1").unwrap_or_default(),
                            framework_id: FrameworkId::new("rt-fw").unwrap_or_default(),
                            agent_id: AgentId::new("agent-1").unwrap_or_default(),
                            role: role2_clone,
                            resources: ResourceBundle::zero(),
                            revocable: false,
                            expires_at_tick: 100,
                        }],
                    ))),
                );
                let non_sched_ev = WireEnvelope::new(
                    3,
                    WireMessage::OperatorCall(Box::new(arbiter_proto::OperatorCall::GetHealth)),
                );
                let body = format!(
                    "{}{}{}",
                    encode_recordio_frame(&sub_ev),
                    encode_recordio_frame(&off_ev),
                    encode_recordio_frame(&non_sched_ev)
                );
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nMesos-Stream-Id: stream-rt-77\r\nContent-Type: application/x-recordio\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                );
                let _ = s.write_all(resp.as_bytes());
            });
        });
        let rt_cli =
            RemoteArbiterClient::new(f_addr, "127.0.0.1:5050".to_owned(), svid2, role2.clone());
        let rt_drv = RemoteFrameworkDriver::new(
            GreedyTestFramework {
                fw_id: FrameworkId::new("rt-fw").unwrap_or_default(),
                role: role2,
                launch_on_offer: true,
                fail_on_offer: false,
                observed_updates: 0,
            },
            rt_cli,
        );
        let mut rt_loop = FrameworkRuntimeLoop::new(rt_drv);
        let follow_ups = rt_loop
            .connect_and_pump_recordio_once(1)
            .unwrap_or_default();
        assert_eq!(follow_ups.len(), 1);
        assert_eq!(rt_loop.active_stream_id, Some("stream-rt-77".to_owned()));
        assert!(rt_loop.driver.runner.is_subscribed);
        let _ = f_handle.join();
        let _ = l_handle.join();

        // Exceeded redirect hops and connect error branches
        let loop_redir_srv = std::net::TcpListener::bind("127.0.0.1:0").ok();
        let loop_redir_addr = loop_redir_srv
            .as_ref()
            .and_then(|l| l.local_addr().ok())
            .map(|a| a.to_string())
            .unwrap_or_default();
        let loop_redir_addr_c = loop_redir_addr.clone();
        let loop_redir_h = std::thread::spawn(move || {
            for _ in 0..2 {
                let _ = loop_redir_srv
                    .as_ref()
                    .and_then(|l| l.accept().ok())
                    .map(|(mut s, _)| {
                        let mut rx = Vec::new();
                        let _ = s.read_to_end(&mut rx);
                        let redir = format!(
                            "HTTP/1.1 307 Temporary Redirect\r\nLocation: http://{loop_redir_addr_c}/api/v1/scheduler\r\nContent-Length: 0\r\n\r\n"
                        );
                        let _ = s.write_all(redir.as_bytes());
                    });
            }
        });
        rt_loop.driver.client.master_http_endpoint = loop_redir_addr;
        assert!(rt_loop.connect_and_pump_recordio_once(2).is_err());
        let _ = loop_redir_h.join();

        "invalid-addr".clone_into(&mut rt_loop.driver.client.master_http_endpoint);
        assert!(rt_loop.connect_and_pump_recordio_once(3).is_err());
    }
}
