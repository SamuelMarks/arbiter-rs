//! Zero-copy binary wire schemas (`rkyv`) and HTTP/JSON DTOs (`serde`) for Arbiter (`arbiter-proto`).
//!
//! Defines versioned protocol envelopes for Master $\leftrightarrow$ Agent and Master $\leftrightarrow$ Framework
//! QUIC streams as well as Mesos v1-style HTTP/REST/SSE operator, scheduler, executor, and job APIs.

#![forbid(missing_docs)]
#![forbid(clippy::missing_docs_in_private_items)]

use arbiter_core::error::{ArbiterError, ArbiterResult, JsonCodecError};
use arbiter_core::ids::{
    AgentId, ContainerId, ExecutorId, ExitCode, FrameworkId, OfferId, OperationId,
    ResourceProviderId, RoleName, StatusUpdateUuid, TaskId, VolumeId,
};
use arbiter_core::platform::{CpuArch, OsKind};
use arbiter_core::resources::ResourceBundle;
use arbiter_core::topology::HardwareTopologyGraph;
use arbiter_core::units::{
    BenchmarkTicks, Bytes, FileReadLength, FileReadOffset, LoggingLevel, PowerMilliwatts,
    SignalNumber, TemperatureMilliCelsius, WeightBasisPoints,
};
use arbiter_core::workload::{
    AgentLossReason, AgentMaintenanceState, CheckpointMode, DiskSource, DrainCompletionMode,
    DynamicReservationSpec, ExecutorInfo, InverseOffer, InverseOfferResponse, KillPolicy,
    MaintenanceSchedule, MasterInfo, OfferFilter, OfferOperation, OfferRescindReason,
    OperationState, PreemptionPolicy, Quota, ResourceOffer, ResourceProviderDiskSpec,
    ResourceProviderInfo, ResourceRequest, Role, TaskGroupSpec, TaskSpec, TaskState,
    VolumeReservationSpec,
};
use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use serde::{Deserialize, Serialize};

/// Current wire protocol schema version (`1`).
pub const WIRE_SCHEMA_VERSION: u16 = 1;

/// Magic 4-byte prefix (`b"ARBW"`) for binary Arbiter wire frames.
pub const WIRE_FRAME_MAGIC: [u8; 4] = *b"ARBW";

/// Fixed byte length (`16`) of a binary [`WireFrameHeader`].
pub const WIRE_FRAME_HEADER_LEN: usize = 16;

/// Maximum permitted binary or `RecordIO` frame payload size (`16 MiB`) to prevent OOM allocation on malformed headers.
pub const MAX_WIRE_FRAME_BYTES: u32 = 16 * 1024 * 1024;

/// Computes an IEEE 802.3 CRC-32 checksum over `bytes`.
///
/// # Arguments
///
/// * `bytes` - Input byte slice.
///
/// # Returns
///
/// 32-bit CRC checksum.
pub fn compute_wire_crc32(bytes: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in bytes {
        crc ^= u32::from(b);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Strongly-typed 16-byte binary wire frame header (`[magic: 4B][version: u16_le][stream_kind: u8][flags: u8][payload_len: u32_le][header_crc32: u32_le]`).
#[derive(
    Debug,
    Default,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
)]
pub struct WireFrameHeader {
    /// Wire protocol schema version (`WIRE_SCHEMA_VERSION`).
    pub protocol_version: u16,
    /// Multiplexed stream kind identifier (`0 = Control`, `1 = Telemetry`, `2 = ArtifactP2p`).
    pub stream_kind: u8,
    /// Frame bitflags (`0` by default).
    pub flags: u8,
    /// Payload length in bytes (`<= MAX_WIRE_FRAME_BYTES`).
    pub payload_len: u32,
    /// IEEE CRC-32 over the first 12 header bytes (`magic || version || stream_kind || flags || payload_len`).
    pub header_crc32: u32,
}

impl WireFrameHeader {
    /// Creates a new [`WireFrameHeader`] for `stream_kind`, `flags`, and `payload_len`.
    ///
    /// # Arguments
    ///
    /// * `stream_kind` - Multiplexed stream identifier byte.
    /// * `flags` - Frame bitflags.
    /// * `payload_len` - Payload byte length.
    ///
    /// # Returns
    ///
    /// Validated [`WireFrameHeader`] with computed `header_crc32`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SerializationError`] if `payload_len > MAX_WIRE_FRAME_BYTES`.
    pub fn new(stream_kind: u8, flags: u8, payload_len: u32) -> ArbiterResult<Self> {
        if payload_len > MAX_WIRE_FRAME_BYTES {
            return Err(ArbiterError::SerializationError {
                format: "ARBW".to_owned(),
                reason: format!(
                    "frame payload length {payload_len} exceeds MAX_WIRE_FRAME_BYTES ({MAX_WIRE_FRAME_BYTES})"
                ),
            });
        }
        let mut prefix = [0_u8; 12];
        let v_bytes = WIRE_SCHEMA_VERSION.to_le_bytes();
        let l_bytes = payload_len.to_le_bytes();
        prefix[0] = WIRE_FRAME_MAGIC[0];
        prefix[1] = WIRE_FRAME_MAGIC[1];
        prefix[2] = WIRE_FRAME_MAGIC[2];
        prefix[3] = WIRE_FRAME_MAGIC[3];
        prefix[4] = v_bytes[0];
        prefix[5] = v_bytes[1];
        prefix[6] = stream_kind;
        prefix[7] = flags;
        prefix[8] = l_bytes[0];
        prefix[9] = l_bytes[1];
        prefix[10] = l_bytes[2];
        prefix[11] = l_bytes[3];
        let header_crc32 = compute_wire_crc32(&prefix);
        Ok(Self {
            protocol_version: WIRE_SCHEMA_VERSION,
            stream_kind,
            flags,
            payload_len,
            header_crc32,
        })
    }

    /// Encodes this [`WireFrameHeader`] into its canonical 16-byte wire representation.
    ///
    /// # Returns
    ///
    /// 16-byte array.
    pub const fn to_bytes(self) -> [u8; WIRE_FRAME_HEADER_LEN] {
        let v = self.protocol_version.to_le_bytes();
        let l = self.payload_len.to_le_bytes();
        let c = self.header_crc32.to_le_bytes();
        [
            WIRE_FRAME_MAGIC[0],
            WIRE_FRAME_MAGIC[1],
            WIRE_FRAME_MAGIC[2],
            WIRE_FRAME_MAGIC[3],
            v[0],
            v[1],
            self.stream_kind,
            self.flags,
            l[0],
            l[1],
            l[2],
            l[3],
            c[0],
            c[1],
            c[2],
            c[3],
        ]
    }

    /// Decodes and validates a 16-byte [`WireFrameHeader`] from `bytes`.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Input byte slice (must be at least [`WIRE_FRAME_HEADER_LEN`] bytes).
    ///
    /// # Returns
    ///
    /// Validated [`WireFrameHeader`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::DeserializationError`] if the slice is shorter than 16 bytes,
    /// has bad magic bytes, fails `header_crc32` verification, has an unsupported version, or
    /// declares `payload_len > MAX_WIRE_FRAME_BYTES`.
    pub fn from_bytes(bytes: &[u8]) -> ArbiterResult<Self> {
        let Some(hdr) = bytes.get(..WIRE_FRAME_HEADER_LEN) else {
            return Err(ArbiterError::DeserializationError {
                format: "ARBW".to_owned(),
                reason: format!(
                    "wire frame header shorter than {WIRE_FRAME_HEADER_LEN} bytes (found {})",
                    bytes.len()
                ),
            });
        };
        if hdr.get(..4).unwrap_or(&[]) != WIRE_FRAME_MAGIC {
            return Err(ArbiterError::DeserializationError {
                format: "ARBW".to_owned(),
                reason: "invalid ARBW wire frame magic bytes".to_owned(),
            });
        }
        let prefix = hdr.get(..12).unwrap_or(&[]);
        let expected_crc = compute_wire_crc32(prefix);
        let mut crc_bytes = [0_u8; 4];
        crc_bytes.copy_from_slice(hdr.get(12..16).unwrap_or(&[0; 4]));
        let header_crc32 = u32::from_le_bytes(crc_bytes);
        if header_crc32 != expected_crc {
            return Err(ArbiterError::DeserializationError {
                format: "ARBW".to_owned(),
                reason: format!(
                    "wire frame header CRC32 mismatch: expected 0x{expected_crc:08x}, found 0x{header_crc32:08x}"
                ),
            });
        }
        let mut ver_bytes = [0_u8; 2];
        ver_bytes.copy_from_slice(hdr.get(4..6).unwrap_or(&[0; 2]));
        let protocol_version = u16::from_le_bytes(ver_bytes);
        if protocol_version != WIRE_SCHEMA_VERSION {
            return Err(ArbiterError::DeserializationError {
                format: "ARBW".to_owned(),
                reason: format!(
                    "unsupported wire frame protocol version {protocol_version} (expected {WIRE_SCHEMA_VERSION})"
                ),
            });
        }
        let stream_kind = hdr.get(6).copied().unwrap_or(0);
        let flags = hdr.get(7).copied().unwrap_or(0);
        let mut len_bytes = [0_u8; 4];
        len_bytes.copy_from_slice(hdr.get(8..12).unwrap_or(&[0; 4]));
        let payload_len = u32::from_le_bytes(len_bytes);
        if payload_len > MAX_WIRE_FRAME_BYTES {
            return Err(ArbiterError::DeserializationError {
                format: "ARBW".to_owned(),
                reason: format!(
                    "wire frame payload length {payload_len} exceeds MAX_WIRE_FRAME_BYTES ({MAX_WIRE_FRAME_BYTES})"
                ),
            });
        }
        Ok(Self {
            protocol_version,
            stream_kind,
            flags,
            payload_len,
            header_crc32,
        })
    }
}

/// Incremental streaming decoder for Mesos v1 `RecordIO` (`<decimal-byte-length>\n<json-payload>`)
/// over arbitrary TCP/HTTP chunk boundaries.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordIoStreamDecoder {
    /// Unconsumed UTF-8 buffer accumulated across TCP chunks.
    buffer: String,
}

impl RecordIoStreamDecoder {
    /// Creates a new empty [`RecordIoStreamDecoder`].
    ///
    /// # Returns
    ///
    /// Initialized [`RecordIoStreamDecoder`].
    pub const fn new() -> Self {
        Self {
            buffer: String::new(),
        }
    }

    /// Returns the number of unconsumed bytes currently buffered.
    ///
    /// # Returns
    ///
    /// Buffered byte count.
    pub fn buffered_bytes(&self) -> usize {
        self.buffer.len()
    }

    /// Appends a newly received UTF-8 chunk and drains all complete [`WireEnvelope`] frames.
    ///
    /// Partial length prefixes or partial payloads remain buffered until subsequent `feed_chunk` calls
    /// complete them.
    ///
    /// # Arguments
    ///
    /// * `chunk` - Incoming stream chunk string slice.
    ///
    /// # Returns
    ///
    /// Vector of all complete [`WireEnvelope`]s decoded after appending `chunk`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::DeserializationError`] or [`ArbiterError::JsonCodec`] if a complete
    /// length prefix is non-numeric, exceeds [`MAX_WIRE_FRAME_BYTES`], or contains invalid JSON.
    pub fn feed_chunk(&mut self, chunk: &str) -> ArbiterResult<Vec<WireEnvelope>> {
        self.buffer.push_str(chunk);
        let mut out = Vec::new();
        while let Some((len_str, rest)) = self.buffer.split_once('\n') {
            let trimmed = len_str.trim();
            let byte_len =
                trimmed
                    .parse::<usize>()
                    .map_err(|_| ArbiterError::DeserializationError {
                        format: "RecordIO".to_owned(),
                        reason: format!("invalid RecordIO byte length '{len_str}'"),
                    })?;
            if byte_len > MAX_WIRE_FRAME_BYTES as usize {
                return Err(ArbiterError::DeserializationError {
                    format: "RecordIO".to_owned(),
                    reason: format!(
                        "RecordIO byte length {byte_len} exceeds MAX_WIRE_FRAME_BYTES ({MAX_WIRE_FRAME_BYTES})"
                    ),
                });
            }
            let Some(json_slice) = rest.get(..byte_len) else {
                // Incomplete payload; wait for more bytes on next `feed_chunk`.
                break;
            };
            let env = WireEnvelope::from_json_str(json_slice)?;
            out.push(env);
            self.buffer = rest.get(byte_len..).unwrap_or_default().to_owned();
        }
        Ok(out)
    }
}

/// Agent registration message sent over QUIC or HTTP (`/api/v1/executor` / control stream).
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize,
)]
pub struct RegisterAgent {
    /// Unique Agent identifier.
    pub agent_id: AgentId,
    /// Host operating system kind.
    pub os_kind: OsKind,
    /// Host CPU architecture.
    pub cpu_arch: CpuArch,
    /// Total hardware capacity bundle.
    pub total_resources: ResourceBundle,
    /// Discovered hardware topology graph.
    pub topology: HardwareTopologyGraph,
}

/// Single-wire Agent heartbeat carrying co-located healthy task IDs.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize,
)]
pub struct AgentHeartbeat {
    /// Agent identifier.
    pub agent_id: AgentId,
    /// Monotonic tick of the heartbeat.
    pub tick: u64,
    /// Active healthy tasks running on this Agent.
    pub healthy_tasks: Vec<TaskId>,
}

/// Periodic hardware telemetry report streamed from an Agent.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize,
)]
pub struct HardwareTelemetryReport {
    /// Agent identifier.
    pub agent_id: AgentId,
    /// Current allocated resource bundle on the Agent.
    pub allocated_resources: ResourceBundle,
    /// Peak device temperature reading in millicelsius.
    pub max_temperature: TemperatureMilliCelsius,
    /// Total Agent power draw in milliwatts.
    pub total_power: PowerMilliwatts,
}

/// Command sent from Master to Agent to launch a scheduled task.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize,
)]
pub struct LaunchTaskCommand {
    /// Target Agent identifier.
    pub agent_id: AgentId,
    /// Task specification to launch.
    pub task: TaskSpec,
}

/// Command sent from Master to Agent to preempt/evict a running task.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize,
)]
pub struct PreemptTaskCommand {
    /// Target Agent identifier.
    pub agent_id: AgentId,
    /// Victim task identifier.
    pub task_id: TaskId,
    /// Eviction policy to execute.
    pub policy: PreemptionPolicy,
}

/// Task lifecycle status update sent from Executor/Agent to Master.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize,
)]
pub struct TaskStatusUpdate {
    /// Task identifier.
    pub task_id: TaskId,
    /// Hosting Agent identifier.
    pub agent_id: AgentId,
    /// New task state.
    pub state: TaskState,
    /// Diagnostic message or exit status reason.
    pub message: String,
}

/// Framework subscription request (`/api/v1/scheduler`).
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize,
)]
pub struct SubscribeFramework {
    /// Framework identifier.
    pub framework_id: FrameworkId,
    /// Scheduling role name.
    pub role: RoleName,
    /// Failover timeout in milliseconds.
    pub failover_timeout_ms: u64,
}

/// Batch of resource offers streamed from Master to a subscribed Framework.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize,
)]
pub struct ResourceOfferBatch {
    /// Target framework identifier.
    pub framework_id: FrameworkId,
    /// Offered resource bundles.
    pub offers: Vec<ResourceOffer>,
}

/// Framework response accepting or operating on a set of resource offers.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize,
)]
pub struct AcceptOffers {
    /// Framework identifier.
    pub framework_id: FrameworkId,
    /// Offer IDs being consumed.
    pub offer_ids: Vec<OfferId>,
    /// Operations to execute on the offered resources.
    pub operations: Vec<OfferOperation>,
}

/// Direct job submission request (`/api/v1/jobs`).
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize,
)]
pub enum SubmitDirectJob {
    /// Single standalone task.
    SingleTask(Box<TaskSpec>),
    /// Atomic gang-scheduled task group.
    GangJob(TaskGroupSpec),
}

/// Complete Mesos v1 `scheduler::Call` union sent from a Framework to the Master (`/api/v1/scheduler`).
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize,
)]
pub enum SchedulerCall {
    /// Subscribes or re-subscribes a Framework: `(sub, checkpoint, autoregister_roles, suppressed_roles)`.
    Subscribe(
        SubscribeFramework,
        CheckpointMode,
        Vec<RoleName>,
        Vec<RoleName>,
    ),
    /// Unregisters a Framework, kills all its active tasks/executors, and releases its dynamic state.
    Teardown(FrameworkId),
    /// Accepts resource offers and applies offer operations: `(accept, operation_id, filter)`.
    Accept(AcceptOffers, Option<OperationId>, OfferFilter),
    /// Declines offered resources and attaches an [`OfferFilter`] suppression window: `(framework_id, offer_ids, filter)`.
    Decline(FrameworkId, Vec<OfferId>, OfferFilter),
    /// Declines or accepts an [`InverseOffer`] for upcoming Agent maintenance: `(framework_id, inverse_offer_ids, accepted)`.
    RespondInverseOffer(FrameworkId, Vec<OfferId>, bool),
    /// Clears all active [`OfferFilter`]s and unsuppresses offer generation: `(framework_id, roles)`.
    Revive(FrameworkId, Vec<RoleName>),
    /// Stops sending resource offers to this Framework for `roles` until `Revive` is called: `(framework_id, roles)`.
    Suppress(FrameworkId, Vec<RoleName>),
    /// Requests termination of a running or staging task: `(framework_id, task_id, agent_id, kill_policy_override)`.
    Kill(FrameworkId, TaskId, Option<AgentId>, Option<KillPolicy>),
    /// Instructs an Agent to gracefully shut down a custom Executor: `(framework_id, executor_id, agent_id)`.
    Shutdown(FrameworkId, ExecutorId, AgentId),
    /// Acknowledges receipt of an at-least-once [`TaskStatusUpdate`]: `(framework_id, agent_id, task_id, status_uuid)`.
    Acknowledge(FrameworkId, AgentId, TaskId, StatusUpdateUuid),
    /// Acknowledges receipt of an offer operation status update: `(framework_id, agent_id, operation_id, status_uuid)`.
    AcknowledgeOperationStatus(FrameworkId, Option<AgentId>, OperationId, StatusUpdateUuid),
    /// Explicit (non-empty) or implicit (empty) task state reconciliation: `(framework_id, tasks)`.
    ReconcileTasks(FrameworkId, Vec<(TaskId, Option<AgentId>)>),
    /// Explicit or implicit reconciliation of offer operations: `(framework_id, operations)`.
    ReconcileOperations(
        FrameworkId,
        Vec<(OperationId, Option<AgentId>, Option<ResourceProviderId>)>,
    ),
    /// Relays an arbitrary binary message from the Framework scheduler to an Executor: `(framework_id, agent_id, executor_id, payload)`.
    Message(FrameworkId, AgentId, ExecutorId, Vec<u8>),
    /// Hints to the Master allocator or cluster autoscaler about desired resource shapes: `(framework_id, requests)`.
    Request(FrameworkId, Vec<ResourceRequest>),
}

/// Complete Mesos v1 `scheduler::Event` notifications streamed from Master to a subscribed Framework.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize,
)]
pub enum SchedulerEvent {
    /// Confirms Framework subscription: `(framework_id, master_info, heartbeat_interval_ticks)`.
    Subscribed(FrameworkId, MasterInfo, BenchmarkTicks),
    /// Delivers a batch of [`ResourceOffer`]s.
    Offers(Vec<ResourceOffer>),
    /// Delivers [`InverseOffer`]s requesting resource reclamation prior to Agent maintenance.
    InverseOffers(Vec<InverseOffer>),
    /// Rescinds a previously issued [`ResourceOffer`] before acceptance: `(offer_id, reason)`.
    Rescind(OfferId, OfferRescindReason),
    /// Cancels a previously issued [`InverseOffer`].
    RescindInverseOffer(OfferId),
    /// Delivers a task lifecycle transition: `(update, status_uuid)`.
    Update(TaskStatusUpdate, Option<StatusUpdateUuid>),
    /// Delivers an offer operation lifecycle state update: `(operation_id, state, message, status_uuid)`.
    OperationUpdate(
        OperationId,
        OperationState,
        String,
        Option<StatusUpdateUuid>,
    ),
    /// Delivers an opaque binary message sent from an Executor to the Framework: `(agent_id, framework_id, executor_id, payload)`.
    Message(AgentId, FrameworkId, ExecutorId, Vec<u8>),
    /// Notifies the Framework that an Agent was lost or marked gone: `(agent_id, reason)`.
    FailureAgentLost(AgentId, AgentLossReason),
    /// Notifies the Framework that an Executor exited or crashed on an Agent: `(agent_id, executor_id, exit_code)`.
    FailureExecutorLost(AgentId, ExecutorId, i32),
    /// Delivers an asynchronous control-plane error to the Framework.
    Error(String),
    /// Periodic stream heartbeat event.
    Heartbeat,
}

/// Complete Mesos v1 `executor::Call` sent from an Executor to its local Agent (`/api/v1/executor`).
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize,
)]
pub enum ExecutorCall {
    /// Subscribes or re-subscribes an Executor: `(framework_id, executor_id, unacknowledged_tasks, unacknowledged_updates)`.
    Subscribe(
        FrameworkId,
        ExecutorId,
        Vec<TaskSpec>,
        Vec<(StatusUpdateUuid, TaskStatusUpdate)>,
    ),
    /// Reports a task state transition to the local Agent: `(executor_id, status, status_uuid)`.
    Update(ExecutorId, TaskStatusUpdate, StatusUpdateUuid),
    /// Sends an opaque binary message to the owning Framework: `(framework_id, executor_id, payload)`.
    Message(FrameworkId, ExecutorId, Vec<u8>),
}

/// Complete Mesos v1 `executor::Event` streamed from the local Agent to a subscribed Executor.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize,
)]
pub enum ExecutorEvent {
    /// Confirms Executor subscription and provides Executor info.
    Subscribed(ExecutorInfo),
    /// Instructs the Executor to launch a single task.
    Launch(Box<TaskSpec>),
    /// Instructs the Default Pod Executor to launch an atomic `TaskGroupSpec`.
    LaunchGroup(TaskGroupSpec),
    /// Instructs the Executor to kill a specific task: `(task_id, kill_policy_override)`.
    Kill(TaskId, Option<KillPolicy>),
    /// Confirms that the Master/Framework acknowledged a previously sent update: `(task_id, status_uuid)`.
    Acknowledged(TaskId, StatusUpdateUuid),
    /// Delivers a binary message from the Framework scheduler to the Executor.
    Message(Vec<u8>),
    /// Instructs the Executor to terminate all hosted tasks and shut itself down within `grace_period_ticks`.
    Shutdown(BenchmarkTicks),
    /// Error notification from the local Agent.
    Error(String),
}

/// Complete Mesos v1 `operator::Call` administrative API (`/api/v1/operator`).
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize,
)]
pub enum OperatorCall {
    /// Checks Master liveness and readiness (`GET_HEALTH`).
    GetHealth,
    /// Queries Master version and wire schema info (`GET_VERSION`).
    GetVersion,
    /// Queries cluster-wide metrics snapshot (`GET_METRICS`).
    GetMetrics,
    /// Queries Master configuration flags (`GET_FLAGS`).
    GetFlags,
    /// Queries active Master leader info (`GET_MASTER`).
    GetMaster,
    /// Lists all registered Agents and their maintenance/health states (`GET_AGENTS`).
    GetAgents,
    /// Lists all registered Frameworks (`GET_FRAMEWORKS`).
    GetFrameworks,
    /// Lists all active Executors across the cluster (`GET_EXECUTORS`).
    GetExecutors,
    /// Lists all tasks and their current lifecycle states (`GET_TASKS`).
    GetTasks,
    /// Dumps combined cluster state (`GET_STATE`).
    GetState,
    /// Lists all roles and their quotas/weights (`GET_ROLES`).
    GetRoles,
    /// Queries role fairness weights (`GET_WEIGHTS`).
    GetWeights,
    /// Updates HDRF fairness weights for one or more roles (`UPDATE_WEIGHTS`).
    UpdateWeights(Vec<(RoleName, WeightBasisPoints)>),
    /// Queries active role quotas (`GET_QUOTA`).
    GetQuota,
    /// Sets or updates a [`Quota`] for a role (`SET_QUOTA`).
    SetQuota(RoleName, Quota),
    /// Removes a role's guaranteed quota (`REMOVE_QUOTA`).
    RemoveQuota(RoleName),
    /// Operator-initiated dynamic resource reservation on an Agent (`RESERVE_RESOURCES`).
    ReserveResources(DynamicReservationSpec),
    /// Operator-initiated dynamic resource unreservation (`UNRESERVE_RESOURCES`).
    UnreserveResources(DynamicReservationSpec),
    /// Operator-initiated persistent volume creation on an Agent: `(agent_id, role, volumes)`.
    CreateVolumes(AgentId, RoleName, Vec<VolumeReservationSpec>),
    /// Operator-initiated persistent volume destruction: `(agent_id, volume_ids)`.
    DestroyVolumes(AgentId, Vec<VolumeId>),
    /// Operator-initiated persistent volume expansion (`GROW_VOLUME`): `(agent_id, volume_id, additional_bytes)`.
    GrowVolume(AgentId, VolumeId, Bytes),
    /// Operator-initiated persistent volume contraction (`SHRINK_VOLUME`): `(agent_id, volume_id, subtract_bytes)`.
    ShrinkVolume(AgentId, VolumeId, Bytes),
    /// Queries current Master/Agent logging verbosity level (`GET_LOGGING_LEVEL`).
    GetLoggingLevel,
    /// Updates Master/Agent logging verbosity level for a duration in ticks (`SET_LOGGING_LEVEL`): `(level, duration_ticks)`.
    SetLoggingLevel(u8, BenchmarkTicks),
    /// Lists files in a sandbox or work directory (`LIST_FILES`): `(path)`.
    ListFiles(String),
    /// Reads a paginated slice of a sandbox file (`READ_FILE`): `(path, offset, length)`.
    ReadFile(String, u64, u64),
    /// Queries the cluster [`MaintenanceSchedule`] (`GET_MAINTENANCE_SCHEDULE`).
    GetMaintenanceSchedule,
    /// Updates the cluster [`MaintenanceSchedule`] and emits [`InverseOffer`]s (`UPDATE_MAINTENANCE_SCHEDULE`).
    UpdateMaintenanceSchedule(MaintenanceSchedule),
    /// Queries per-Agent [`AgentMaintenanceState`] (`GET_MAINTENANCE_STATUS`).
    GetMaintenanceStatus,
    /// Transitions Agents into active maintenance (`Deactivated` / `Down`) (`START_MAINTENANCE`).
    StartMaintenance(Vec<AgentId>),
    /// Completes maintenance and reactivates Agents back to `Normal` (`STOP_MAINTENANCE`).
    StopMaintenance(Vec<AgentId>),
    /// Starts automated task draining on an Agent: `(agent_id, max_grace_period_ticks, completion_mode)`.
    DrainAgent(AgentId, BenchmarkTicks, DrainCompletionMode),
    /// Deactivates an Agent so it receives no new offers or placements (`DEACTIVATE_AGENT`).
    DeactivateAgent(AgentId),
    /// Reactivates a drained or deactivated Agent back to `Normal` (`REACTIVATE_AGENT`).
    ReactivateAgent(AgentId),
    /// Permanently marks an unreachable or decommissioned Agent gone (`MARK_AGENT_GONE`).
    MarkAgentGone(AgentId),
    /// Subscribes to the streaming Operator event bus (`SUBSCRIBE`).
    SubscribeOperatorEvents,
}

/// Response payload returned by `MasterNode::handle_operator_call`.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize,
)]
pub enum OperatorResponse {
    /// Health check status (`true` = healthy).
    Health(bool),
    /// Version and wire schema info: `(version, wire_schema_version)`.
    Version(String, u16),
    /// Prometheus/key-value metrics summary: `(total_agents, total_tasks, active_offers)`.
    Metrics(u64, u64, u64),
    /// Master configuration flags: `(agent_lease_ttl_ticks, offer_ttl_ticks)`.
    Flags(u64, u64),
    /// Master leader info.
    Master(MasterInfo),
    /// Registered Agent IDs and their health/maintenance states.
    Agents(Vec<(AgentId, bool, AgentMaintenanceState, ResourceBundle)>),
    /// Registered Framework IDs and their primary roles.
    Frameworks(Vec<(FrameworkId, RoleName, bool)>),
    /// Active Executor descriptors across the cluster.
    Executors(Vec<ExecutorInfo>),
    /// Current tasks and their states/agents.
    Tasks(Vec<(TaskId, TaskState, AgentId, ResourceBundle)>),
    /// Roles and their quota/weight configurations.
    Roles(Vec<Role>),
    /// Role fairness weights.
    Weights(Vec<(RoleName, WeightBasisPoints)>),
    /// Active maintenance schedule.
    MaintenanceSchedule(MaintenanceSchedule),
    /// Per-Agent maintenance status map.
    MaintenanceStatus(Vec<(AgentId, AgentMaintenanceState)>),
    /// Active logging verbosity level (`0..=3`).
    LoggingLevel(u8),
    /// Directory listing entries (`LIST_FILES`).
    FileList(Vec<String>),
    /// Paginated file read response (`READ_FILE`): `(offset, data)`.
    FileChunk(u64, String),
    /// Generic mutation acknowledgement message.
    Ok(String),
}

/// Streaming Operator Event emitted to subscribed Operator clients (`SUBSCRIBE`).
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize,
)]
pub enum OperatorEvent {
    /// A new task was added to the cluster: `(task_id, agent_id)`.
    TaskAdded(TaskId, AgentId),
    /// An existing task transitioned state: `(task_id, state)`.
    TaskUpdated(TaskId, TaskState),
    /// A Framework subscribed: `(framework_id, role)`.
    FrameworkAdded(FrameworkId, RoleName),
    /// A Framework updated its configuration or re-subscribed.
    FrameworkUpdated(FrameworkId),
    /// A Framework tore down or timed out.
    FrameworkRemoved(FrameworkId),
    /// An Agent registered with the Master.
    AgentAdded(AgentId),
    /// An Agent was lost or marked gone: `(agent_id, reason)`.
    AgentRemoved(AgentId, AgentLossReason),
}

impl SchedulerCall {
    /// Constructs a [`SchedulerCall::RespondInverseOffer`] using a strongly-typed [`InverseOfferResponse`].
    ///
    /// # Arguments
    ///
    /// * `framework_id` - Subscribed [`FrameworkId`].
    /// * `inverse_offer_ids` - [`OfferId`]s of the inverse offers being answered.
    /// * `response` - Strongly-typed [`InverseOfferResponse`].
    ///
    /// # Returns
    ///
    /// [`SchedulerCall::RespondInverseOffer`].
    pub const fn respond_inverse_offer_typed(
        framework_id: FrameworkId,
        inverse_offer_ids: Vec<OfferId>,
        response: InverseOfferResponse,
    ) -> Self {
        Self::RespondInverseOffer(framework_id, inverse_offer_ids, response.is_accepted())
    }
}

impl OperatorCall {
    /// Constructs an [`OperatorCall::SetLoggingLevel`] from a strongly-typed [`LoggingLevel`].
    ///
    /// # Arguments
    ///
    /// * `level` - Target [`LoggingLevel`].
    /// * `duration_ticks` - Duration in [`BenchmarkTicks`].
    ///
    /// # Returns
    ///
    /// [`OperatorCall::SetLoggingLevel`].
    pub const fn set_logging_level_typed(
        level: LoggingLevel,
        duration_ticks: BenchmarkTicks,
    ) -> Self {
        Self::SetLoggingLevel(level.as_u8(), duration_ticks)
    }

    /// Constructs an [`OperatorCall::ReadFile`] from strongly-typed [`FileReadOffset`] and [`FileReadLength`].
    ///
    /// # Arguments
    ///
    /// * `path` - Sandbox file path string.
    /// * `offset` - [`FileReadOffset`].
    /// * `length` - [`FileReadLength`].
    ///
    /// # Returns
    ///
    /// [`OperatorCall::ReadFile`].
    pub const fn read_file_typed(
        path: String,
        offset: FileReadOffset,
        length: FileReadLength,
    ) -> Self {
        Self::ReadFile(path, offset.get(), length.get())
    }
}

impl OperatorResponse {
    /// Constructs an [`OperatorResponse::LoggingLevel`] from a strongly-typed [`LoggingLevel`].
    ///
    /// # Arguments
    ///
    /// * `level` - Active [`LoggingLevel`].
    ///
    /// # Returns
    ///
    /// [`OperatorResponse::LoggingLevel`].
    pub const fn logging_level_typed(level: LoggingLevel) -> Self {
        Self::LoggingLevel(level.as_u8())
    }
}

/// Active container runtime status entry returned by [`AgentOperatorCall::GetContainers`] (`GET_CONTAINERS`).
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize,
)]
pub struct ContainerStatusInfo {
    /// Container identifier (`ContainerId`).
    pub container_id: ContainerId,
    /// Optional parent container identifier for nested containers (`None` for top-level executor containers).
    pub parent_container_id: Option<ContainerId>,
    /// Hosting Executor identifier.
    pub executor_id: ExecutorId,
    ///Allocated resource bundle for this container.
    pub allocated_resources: ResourceBundle,
    /// Whether the container is currently running (`true`) or exited (`false`).
    pub running: bool,
    /// Exit status code if the container has terminated (`None` while running).
    pub exit_status: Option<ExitCode>,
}

/// Complete Mesos v1 Agent `operator::Call` administrative and nested-container API.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize,
)]
pub enum AgentOperatorCall {
    /// Lists all active top-level and nested containers on the Agent (`GET_CONTAINERS`).
    GetContainers,
    /// Launches a nested container inside an existing parent container (`LAUNCH_NESTED_CONTAINER`):
    /// `(parent_container_id, nested_container_id, command, args, env, resources)`.
    LaunchNestedContainer(
        ContainerId,
        ContainerId,
        String,
        Vec<String>,
        Vec<(String, String)>,
        ResourceBundle,
    ),
    /// Waits for a nested container to terminate and returns its exit status (`WAIT_NESTED_CONTAINER`).
    WaitNestedContainer(ContainerId),
    /// Delivers a POSIX signal to a nested container (`KILL_NESTED_CONTAINER`): `(nested_container_id, signal)`.
    KillNestedContainer(ContainerId, SignalNumber),
    /// Removes a terminated nested container's sandbox and cgroup state (`REMOVE_NESTED_CONTAINER`).
    RemoveNestedContainer(ContainerId),
    /// Launches an interactive debugging session inside a container (`LAUNCH_NESTED_CONTAINER_SESSION`):
    /// `(parent_container_id, session_container_id, command, args)`.
    LaunchNestedContainerSession(ContainerId, ContainerId, String, Vec<String>),
    /// Streams standard input bytes into an interactive nested container session (`ATTACH_CONTAINER_INPUT`):
    /// `(container_id, stdin_bytes)`.
    AttachContainerInput(ContainerId, Vec<u8>),
    /// Reads buffered standard output and standard error from a nested container session (`ATTACH_CONTAINER_OUTPUT`).
    AttachContainerOutput(ContainerId),
    /// Garbage-collects unreferenced OCI container layers and cached artifacts (`PRUNE_IMAGES`):
    /// `(excluded_image_refs)`.
    PruneImages(Vec<String>),
}

/// Response payload returned by `AgentSupervisor::handle_agent_operator_call`.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize,
)]
pub enum AgentOperatorResponse {
    /// Active top-level and nested containers (`GET_CONTAINERS`).
    Containers(Vec<ContainerStatusInfo>),
    /// Wait result for a nested container (`WAIT_NESTED_CONTAINER`): `(container_id, exit_code)`.
    NestedContainerWaitResult(ContainerId, ExitCode),
    /// Attached stdout/stderr output stream chunk (`ATTACH_CONTAINER_OUTPUT`): `(container_id, stdout_bytes, stderr_bytes)`.
    ContainerOutputChunk(ContainerId, Vec<u8>, Vec<u8>),
    /// Image & artifact cache pruning summary (`PRUNE_IMAGES`): `(reclaimed_entries, reclaimed_bytes)`.
    ImagesPruned(u64, Bytes),
    /// Generic mutation acknowledgement.
    Ok(String),
}

/// Complete Mesos v1 `resource_provider::Call` sent from a Local or External CSI Resource Provider
/// to the Agent/Master (`/api/v1/resource_provider`).
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize,
)]
pub enum ResourceProviderCall {
    /// Subscribes or re-subscribes a Resource Provider with its [`ResourceProviderInfo`].
    Subscribe(ResourceProviderInfo),
    /// Reports an operation status transition: `(provider_id, operation_id, state, status_uuid, converted_disk)`.
    UpdateOperationStatus(
        ResourceProviderId,
        OperationId,
        OperationState,
        StatusUpdateUuid,
        Option<ResourceProviderDiskSpec>,
    ),
    /// Updates the Resource Provider's advertised total resources and state version:
    /// `(provider_id, state_version_uuid, advertised_disks)`.
    UpdateState(
        ResourceProviderId,
        StatusUpdateUuid,
        Vec<(DiskSource, Bytes)>,
    ),
    /// Updates publish resources status in response to `PublishResources`: `(provider_id, status_uuid, ok)`.
    UpdatePublishResourcesStatus(ResourceProviderId, StatusUpdateUuid, bool),
}

/// Complete Mesos v1 `resource_provider::Event` streamed from the Agent/Master to a subscribed Resource Provider.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize,
)]
pub enum ResourceProviderEvent {
    /// Confirms subscription and assigns/confirms the [`ResourceProviderId`].
    Subscribed(ResourceProviderId),
    /// Instructs the Resource Provider to apply an offer operation (`CREATE_DISK`, `DESTROY_DISK`, `CREATE`, `DESTROY`):
    /// `(operation_id, operation, status_uuid)`.
    ApplyOperation(OperationId, OfferOperation, StatusUpdateUuid),
    /// Instructs the Resource Provider to stage/publish disk resources prior to task launch:
    /// `(status_uuid, disks)`.
    PublishResources(StatusUpdateUuid, Vec<ResourceProviderDiskSpec>),
    /// Confirms that the Master acknowledged an operation status update: `(operation_id, status_uuid)`.
    AcknowledgeOperationStatus(OperationId, StatusUpdateUuid),
    /// Instructs the Resource Provider to reconcile unknown operations: `(operation_ids)`.
    ReconcileOperations(Vec<OperationId>),
    /// Instructs the Resource Provider to tear down and clean up state.
    Teardown,
}

/// Raft consensus peer-to-peer wire RPC messages (`arbiter-store::raft` over `arbiter-net`).
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize,
)]
pub enum RaftRpcMessage {
    /// Pre-election `PreVote` RPC: `(next_term, candidate_id, last_log_index, last_log_term)`.
    PreVote(u64, String, u64, u64),
    /// Voter response to `PreVote`: `(term, vote_granted, voter_id)`.
    PreVoteResponse(u64, bool, String),
    /// Candidate `RequestVote` RPC: `(term, candidate_id, last_log_index, last_log_term)`.
    RequestVote(u64, String, u64, u64),
    /// Voter response to `RequestVote`: `(term, vote_granted, voter_id)`.
    RequestVoteResponse(u64, bool, String),
    /// Leader `AppendEntries` RPC: `(term, leader_id, prev_log_index, prev_log_term, entries, leader_commit)`.
    AppendEntries(
        u64,
        String,
        u64,
        u64,
        Vec<(u64, u64, u32, String, Vec<u8>)>,
        u64,
    ),
    /// Follower response to `AppendEntries`: `(term, success, match_index, follower_id)`.
    AppendEntriesResponse(u64, bool, u64, String),
    /// Leader `InstallSnapshot` RPC: `(term, leader_id, last_included_index, last_included_term, crc32, kv_pairs)`.
    InstallSnapshot(u64, String, u64, u64, u32, Vec<(String, Vec<u8>)>),
    /// Follower response to `InstallSnapshot`: `(term, success, follower_id)`.
    InstallSnapshotResponse(u64, bool, String),
}

/// Unified control-plane wire message payload.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize,
)]
pub enum WireMessage {
    /// Agent registration.
    RegisterAgent(Box<RegisterAgent>),
    /// Agent single-wire heartbeat.
    AgentHeartbeat(AgentHeartbeat),
    /// Agent hardware telemetry report.
    HardwareTelemetryReport(HardwareTelemetryReport),
    /// Master launch task command.
    LaunchTaskCommand(Box<LaunchTaskCommand>),
    /// Master preempt task command.
    PreemptTaskCommand(PreemptionCommandWrapper),
    /// Task status update.
    TaskStatusUpdate(TaskStatusUpdate),
    /// Framework subscription.
    SubscribeFramework(SubscribeFramework),
    /// Resource offer batch.
    ResourceOfferBatch(ResourceOfferBatch),
    /// Offer acceptance.
    AcceptOffers(AcceptOffers),
    /// Direct job submission.
    SubmitDirectJob(SubmitDirectJob),
    /// Mesos v1 Scheduler API Call.
    SchedulerCall(Box<SchedulerCall>),
    /// Mesos v1 Scheduler API Event.
    SchedulerEvent(Box<SchedulerEvent>),
    /// Mesos v1 Executor API Call.
    ExecutorCall(Box<ExecutorCall>),
    /// Mesos v1 Executor API Event.
    ExecutorEvent(Box<ExecutorEvent>),
    /// Mesos v1 Operator API Call.
    OperatorCall(Box<OperatorCall>),
    /// Mesos v1 Operator API Response.
    OperatorResponse(Box<OperatorResponse>),
    /// Mesos v1 Operator Streaming Event.
    OperatorEvent(OperatorEvent),
    /// Mesos v1 Resource Provider API Call (`/api/v1/resource_provider`).
    ResourceProviderCall(Box<ResourceProviderCall>),
    /// Mesos v1 Resource Provider API Event (`/api/v1/resource_provider`).
    ResourceProviderEvent(Box<ResourceProviderEvent>),
    /// Mesos v1 Agent Operator & Nested Container API Call.
    AgentOperatorCall(Box<AgentOperatorCall>),
    /// Mesos v1 Agent Operator & Nested Container API Response.
    AgentOperatorResponse(Box<AgentOperatorResponse>),
    /// Embedded Raft peer-to-peer consensus RPC.
    RaftRpc(Box<RaftRpcMessage>),
}

/// Type alias preserving compatibility for `PreemptTaskCommand` inside `WireMessage`.
pub type PreemptionCommandWrapper = PreemptTaskCommand;

/// Encodes a [`WireEnvelope`] using Mesos v1 HTTP `RecordIO` framing (`<byte_length>\n<json_bytes>`).
///
/// # Arguments
///
/// * `envelope` - [`WireEnvelope`] to encode.
///
/// # Returns
///
/// `RecordIO`-framed string (`"<len>\n<json>"`).
pub fn encode_recordio_frame(envelope: &WireEnvelope) -> String {
    let json = envelope.to_json_string();
    let byte_len = json.len();
    format!("{byte_len}\n{json}")
}

/// Decodes one or more concatenated Mesos v1 `RecordIO` frames (`<byte_length>\n<json_bytes>`) into [`WireEnvelope`]s.
///
/// # Arguments
///
/// * `input` - Raw `RecordIO` stream string slice.
///
/// # Returns
///
/// Vector of decoded [`WireEnvelope`]s.
///
/// # Errors
///
/// Returns [`ArbiterError::DeserializationError`] or [`ArbiterError::JsonCodec`] if a length prefix
/// is malformed, truncated, or contains invalid JSON.
pub fn decode_recordio_frames(input: &str) -> ArbiterResult<Vec<WireEnvelope>> {
    let mut cursor = input;
    let mut frames = Vec::new();
    while !cursor.is_empty() {
        let Some((len_str, rest)) = cursor.split_once('\n') else {
            return Err(ArbiterError::DeserializationError {
                format: "RecordIO".to_owned(),
                reason: "missing newline after RecordIO byte length prefix".to_owned(),
            });
        };
        let byte_len =
            len_str
                .trim()
                .parse::<usize>()
                .map_err(|_| ArbiterError::DeserializationError {
                    format: "RecordIO".to_owned(),
                    reason: format!("invalid RecordIO byte length '{len_str}'"),
                })?;
        let Some(json_slice) = rest.get(..byte_len) else {
            return Err(ArbiterError::DeserializationError {
                format: "RecordIO".to_owned(),
                reason: format!(
                    "truncated RecordIO frame: expected {byte_len} bytes, found {}",
                    rest.len()
                ),
            });
        };
        let env = WireEnvelope::from_json_str(json_slice)?;
        frames.push(env);
        cursor = rest.get(byte_len..).unwrap_or_default();
    }
    Ok(frames)
}

/// Versioned wire envelope wrapping any [`WireMessage`] for binary (`rkyv`) or JSON (`serde`) transport.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize,
)]
pub struct WireEnvelope {
    /// Wire schema version (must equal [`WIRE_SCHEMA_VERSION`]).
    pub version: u16,
    /// Monotonic sequence number of the frame.
    pub sequence: u64,
    /// Inner protocol message.
    pub message: WireMessage,
}

impl WireEnvelope {
    /// Creates a new [`WireEnvelope`] with [`WIRE_SCHEMA_VERSION`].
    ///
    /// # Arguments
    ///
    /// * `sequence` - Frame sequence number.
    /// * `message` - Inner [`WireMessage`].
    ///
    /// # Returns
    ///
    /// Versioned [`WireEnvelope`].
    pub const fn new(sequence: u64, message: WireMessage) -> Self {
        Self {
            version: WIRE_SCHEMA_VERSION,
            sequence,
            message,
        }
    }

    /// Encodes this [`WireEnvelope`] into a 16-byte-aligned zero-copy `rkyv` buffer.
    ///
    /// # Returns
    ///
    /// Aligned `rkyv::util::AlignedVec<16>` buffer.
    pub fn to_aligned_bytes(&self) -> rkyv::util::AlignedVec<16> {
        rkyv::to_bytes::<rkyv::rancor::Error>(self).unwrap_or_default()
    }

    /// Encodes this [`WireEnvelope`] into zero-copy `rkyv` binary bytes.
    ///
    /// # Returns
    ///
    /// Binary payload `Vec<u8>`.
    pub fn to_rkyv_bytes(&self) -> Vec<u8> {
        self.to_aligned_bytes().into_vec()
    }

    /// Validates and decodes a [`WireEnvelope`] from `rkyv` binary bytes, enforcing schema version checking.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Raw binary frame slice.
    ///
    /// # Returns
    ///
    /// Decoded [`WireEnvelope`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::RkyvCodec`] if the byte slice fails `rkyv` `bytecheck`
    /// validation or [`ArbiterError::DeserializationError`] if it has an unsupported `version`.
    pub fn from_rkyv_bytes(bytes: &[u8]) -> ArbiterResult<Self> {
        let mut aligned = rkyv::util::AlignedVec::<16>::with_capacity(bytes.len());
        aligned.extend_from_slice(bytes);
        let decoded: Self = rkyv::from_bytes::<Self, rkyv::rancor::Error>(&aligned)
            .map_err(arbiter_core::error::RkyvCodecError::from)?;
        if decoded.version != WIRE_SCHEMA_VERSION {
            return Err(ArbiterError::DeserializationError {
                format: "rkyv".to_owned(),
                reason: format!(
                    "unsupported wire schema version {} (expected {})",
                    decoded.version, WIRE_SCHEMA_VERSION
                ),
            });
        }
        Ok(decoded)
    }

    /// Validates and accesses an [`ArchivedWireEnvelope`] directly from an aligned `rkyv` byte slice
    /// without heap deserialization, enforcing [`WIRE_SCHEMA_VERSION`].
    ///
    /// # Arguments
    ///
    /// * `aligned_bytes` - 16-byte-aligned `rkyv` binary frame slice.
    ///
    /// # Returns
    ///
    /// Zero-copy reference `&ArchivedWireEnvelope`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::RkyvCodec`] if `rkyv::access` (`bytecheck`) fails or
    /// [`ArbiterError::DeserializationError`] if `version != WIRE_SCHEMA_VERSION`.
    pub fn access_archived(aligned_bytes: &[u8]) -> ArbiterResult<&ArchivedWireEnvelope> {
        let archived = rkyv::access::<ArchivedWireEnvelope, rkyv::rancor::Error>(aligned_bytes)
            .map_err(arbiter_core::error::RkyvCodecError::from)?;
        let ver = archived.version.to_native();
        if ver != WIRE_SCHEMA_VERSION {
            return Err(ArbiterError::DeserializationError {
                format: "rkyv".to_owned(),
                reason: format!(
                    "unsupported wire schema version {ver} (expected {WIRE_SCHEMA_VERSION})"
                ),
            });
        }
        Ok(archived)
    }

    /// Alias for [`Self::access_archived`] providing zero-copy inspection of an [`ArchivedWireEnvelope`].
    ///
    /// # Arguments
    ///
    /// * `aligned_bytes` - 16-byte-aligned `rkyv` binary frame slice.
    ///
    /// # Returns
    ///
    /// Zero-copy reference `&ArchivedWireEnvelope`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::RkyvCodec`] if `rkyv::access` (`bytecheck`) fails or
    /// [`ArbiterError::DeserializationError`] if `version != WIRE_SCHEMA_VERSION`.
    pub fn view_archived(aligned_bytes: &[u8]) -> ArbiterResult<&ArchivedWireEnvelope> {
        Self::access_archived(aligned_bytes)
    }

    /// Inspects an `ARBW`-framed or raw aligned `rkyv` buffer in zero-copy mode, returning
    /// `(version, sequence, message_kind_tag)` without deserializing the full [`WireEnvelope`].
    ///
    /// # Arguments
    ///
    /// * `aligned_rkyv_bytes` - 16-byte-aligned `rkyv` payload bytes.
    ///
    /// # Returns
    ///
    /// [`ZeroCopyFrameHeaderSummary`] read directly from the archived root struct.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::RkyvCodec`] or [`ArbiterError::DeserializationError`] if invalid.
    pub fn inspect_framed_header_zero_copy(
        aligned_rkyv_bytes: &[u8],
    ) -> ArbiterResult<ZeroCopyFrameHeaderSummary> {
        let archived = Self::access_archived(aligned_rkyv_bytes)?;
        let kind_name = match archived.message {
            ArchivedWireMessage::RegisterAgent(_) => "RegisterAgent",
            ArchivedWireMessage::AgentHeartbeat(_) => "AgentHeartbeat",
            ArchivedWireMessage::HardwareTelemetryReport(_) => "HardwareTelemetryReport",
            ArchivedWireMessage::LaunchTaskCommand(_) => "LaunchTaskCommand",
            ArchivedWireMessage::PreemptTaskCommand(_) => "PreemptTaskCommand",
            ArchivedWireMessage::TaskStatusUpdate(_) => "TaskStatusUpdate",
            ArchivedWireMessage::SubscribeFramework(_) => "SubscribeFramework",
            ArchivedWireMessage::ResourceOfferBatch(_) => "ResourceOfferBatch",
            ArchivedWireMessage::AcceptOffers(_) => "AcceptOffers",
            ArchivedWireMessage::SubmitDirectJob(_) => "SubmitDirectJob",
            ArchivedWireMessage::SchedulerCall(_) => "SchedulerCall",
            ArchivedWireMessage::SchedulerEvent(_) => "SchedulerEvent",
            ArchivedWireMessage::ExecutorCall(_) => "ExecutorCall",
            ArchivedWireMessage::ExecutorEvent(_) => "ExecutorEvent",
            ArchivedWireMessage::OperatorCall(_) => "OperatorCall",
            ArchivedWireMessage::OperatorResponse(_) => "OperatorResponse",
            ArchivedWireMessage::OperatorEvent(_) => "OperatorEvent",
            ArchivedWireMessage::ResourceProviderCall(_) => "ResourceProviderCall",
            ArchivedWireMessage::ResourceProviderEvent(_) => "ResourceProviderEvent",
            ArchivedWireMessage::AgentOperatorCall(_) => "AgentOperatorCall",
            ArchivedWireMessage::AgentOperatorResponse(_) => "AgentOperatorResponse",
            ArchivedWireMessage::RaftRpc(_) => "RaftRpc",
        };
        Ok(ZeroCopyFrameHeaderSummary {
            version: archived.version.to_native(),
            sequence: archived.sequence.to_native(),
            message_kind: kind_name,
        })
    }

    /// Encodes this [`WireEnvelope`] as an HTTP/REST JSON string.
    ///
    /// # Returns
    ///
    /// JSON string representation.
    pub fn to_json_string(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// Decodes and validates a [`WireEnvelope`] from an HTTP/REST JSON string.
    ///
    /// # Arguments
    ///
    /// * `json` - Input JSON string slice.
    ///
    /// # Returns
    ///
    /// Decoded [`WireEnvelope`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::JsonCodec`] if JSON parsing fails, or
    /// [`ArbiterError::DeserializationError`] if `version != WIRE_SCHEMA_VERSION`.
    pub fn from_json_str(json: &str) -> ArbiterResult<Self> {
        let decoded: Self = serde_json::from_str(json).map_err(JsonCodecError::from)?;
        if decoded.version != WIRE_SCHEMA_VERSION {
            return Err(ArbiterError::DeserializationError {
                format: "json".to_owned(),
                reason: format!(
                    "unsupported wire schema version {} (expected {})",
                    decoded.version, WIRE_SCHEMA_VERSION
                ),
            });
        }
        Ok(decoded)
    }
}

/// Zero-copy header inspection summary extracted directly from an [`ArchivedWireEnvelope`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ZeroCopyFrameHeaderSummary {
    /// Wire schema version (`WIRE_SCHEMA_VERSION`).
    pub version: u16,
    /// Monotonic frame sequence number.
    pub sequence: u64,
    /// Static discriminant name of the inner [`ArchivedWireMessage`].
    pub message_kind: &'static str,
}

/// Content-Type negotiation mode for HTTP/QUIC wire payloads.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WireCodecContentType {
    /// `application/json` (standard Mesos v1 JSON DTO encoding).
    #[default]
    ApplicationJson,
    /// `application/x-protobuf` (Mesos v1 Protobuf-compatible JSON/RecordIO mapping).
    ApplicationProtobuf,
    /// `application/x-rkyv` (Arbiter zero-copy binary `rkyv` framing).
    ApplicationRkyv,
}

impl WireCodecContentType {
    /// Parses an HTTP `Content-Type` header value into a [`WireCodecContentType`].
    ///
    /// # Arguments
    ///
    /// * `header_value` - Raw `Content-Type` header string.
    ///
    /// # Returns
    ///
    /// Negotiated [`WireCodecContentType`].
    pub fn from_content_type_header(header_value: &str) -> Self {
        let lower = header_value.trim().to_ascii_lowercase();
        if lower.contains("application/x-rkyv") {
            Self::ApplicationRkyv
        } else if lower.contains("application/x-protobuf") {
            Self::ApplicationProtobuf
        } else {
            Self::ApplicationJson
        }
    }

    /// Returns the canonical MIME type string for this [`WireCodecContentType`].
    ///
    /// # Returns
    ///
    /// Static MIME string.
    pub const fn as_mime_str(self) -> &'static str {
        match self {
            Self::ApplicationJson => "application/json",
            Self::ApplicationProtobuf => "application/x-protobuf",
            Self::ApplicationRkyv => "application/x-rkyv",
        }
    }
}

/// Mesos v1-style HTTP API endpoint path classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ApiEndpoint {
    /// `/api/v1/scheduler` (Framework subscription, offer streams, offer acceptance).
    Scheduler,
    /// `/api/v1/executor` (Agent & Executor registration, heartbeats, status updates).
    Executor,
    /// `/api/v1/operator` (Cluster inspection, quota updates, maintenance).
    Operator,
    /// `/api/v1/jobs` (Direct task and gang job submissions).
    Jobs,
    /// `/api/v1/resource_provider` (CSI and external Resource Provider registration and disk operations).
    ResourceProvider,
    /// `/api/v1/files` (Sandbox file browse, paginated read, and download API).
    Files,
}

impl ApiEndpoint {
    /// Parses a request path into an [`ApiEndpoint`].
    ///
    /// # Arguments
    ///
    /// * `path` - HTTP URI path.
    ///
    /// # Returns
    ///
    /// Matching [`ApiEndpoint`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::HttpHandlerError`] with status `404` if the path is unknown.
    pub fn from_path(path: &str) -> ArbiterResult<Self> {
        match path {
            "/api/v1/scheduler" => Ok(Self::Scheduler),
            "/api/v1/executor" => Ok(Self::Executor),
            "/api/v1/operator" => Ok(Self::Operator),
            "/api/v1/jobs" => Ok(Self::Jobs),
            "/api/v1/resource_provider" => Ok(Self::ResourceProvider),
            "/api/v1/files" => Ok(Self::Files),
            _ => Err(ArbiterError::HttpHandlerError {
                status_code: 404,
                message: format!("unknown API endpoint path '{path}'"),
            }),
        }
    }

    /// Returns the canonical HTTP URI path for this endpoint.
    ///
    /// # Returns
    ///
    /// Static path string.
    pub const fn as_path(self) -> &'static str {
        match self {
            Self::Scheduler => "/api/v1/scheduler",
            Self::Executor => "/api/v1/executor",
            Self::Operator => "/api/v1/operator",
            Self::Jobs => "/api/v1/jobs",
            Self::ResourceProvider => "/api/v1/resource_provider",
            Self::Files => "/api/v1/files",
        }
    }
}

/// Returns the crate identifier for verification.
///
/// # Returns
///
/// The static crate name `"arbiter-proto"`.
pub const fn crate_name() -> &'static str {
    "arbiter-proto"
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn test_crate_name_and_api_endpoints() {
        assert_eq!(crate_name(), "arbiter-proto");
        let endpoints = [
            ("/api/v1/scheduler", ApiEndpoint::Scheduler),
            ("/api/v1/executor", ApiEndpoint::Executor),
            ("/api/v1/operator", ApiEndpoint::Operator),
            ("/api/v1/jobs", ApiEndpoint::Jobs),
            ("/api/v1/resource_provider", ApiEndpoint::ResourceProvider),
            ("/api/v1/files", ApiEndpoint::Files),
        ];
        for (path, expected) in endpoints {
            assert_eq!(ApiEndpoint::from_path(path), Ok(expected));
            assert_eq!(expected.as_path(), path);
        }
        assert!(ApiEndpoint::from_path("/api/v1/unknown").is_err());

        let inv_call = SchedulerCall::respond_inverse_offer_typed(
            FrameworkId::default(),
            Vec::new(),
            InverseOfferResponse::AcceptMaintenance,
        );
        assert_eq!(
            inv_call,
            SchedulerCall::RespondInverseOffer(FrameworkId::default(), Vec::new(), true)
        );
        let log_call =
            OperatorCall::set_logging_level_typed(LoggingLevel::Debug, BenchmarkTicks::new(5));
        assert_eq!(
            log_call,
            OperatorCall::SetLoggingLevel(3, BenchmarkTicks::new(5))
        );
        let read_call = OperatorCall::read_file_typed(
            "/sandbox/stdout".to_owned(),
            FileReadOffset::new(10),
            FileReadLength::new(100),
        );
        assert_eq!(
            read_call,
            OperatorCall::ReadFile("/sandbox/stdout".to_owned(), 10, 100)
        );
        let log_resp = OperatorResponse::logging_level_typed(LoggingLevel::Info);
        assert_eq!(log_resp, OperatorResponse::LoggingLevel(2));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_rkyv_and_json_roundtrip_and_version_validation() {
        let hb = WireMessage::AgentHeartbeat(AgentHeartbeat {
            agent_id: AgentId::new("agent-1").unwrap_or_default(),
            tick: 42,
            healthy_tasks: vec![TaskId::new("t-1").unwrap_or_default()],
        });
        let env = WireEnvelope::new(100, hb);

        // rkyv roundtrip & zero-copy access_archived / view_archived
        let bin = env.to_rkyv_bytes();
        let aligned = env.to_aligned_bytes();
        let archived = WireEnvelope::access_archived(&aligned);
        assert!(archived.is_ok());
        assert_eq!(archived.map(|a| a.sequence.to_native()), Ok(env.sequence));
        assert_eq!(
            WireEnvelope::view_archived(&aligned).map(|a| a.sequence.to_native()),
            Ok(env.sequence)
        );
        assert_eq!(WireEnvelope::from_rkyv_bytes(&bin), Ok(env.clone()));

        // Corrupted binary payload rejected with ArbiterError::RkyvCodec
        assert!(matches!(
            WireEnvelope::from_rkyv_bytes(b"corrupted"),
            Err(ArbiterError::RkyvCodec(_))
        ));
        assert!(matches!(
            WireEnvelope::access_archived(b"corrupted"),
            Err(ArbiterError::RkyvCodec(_))
        ));
        assert!(matches!(
            WireEnvelope::view_archived(b"corrupted"),
            Err(ArbiterError::RkyvCodec(_))
        ));

        // Unsupported version in rkyv rejected
        let mut bad_ver = env.clone();
        bad_ver.version = 99;
        let bad_bin = bad_ver.to_rkyv_bytes();
        let bad_aligned = bad_ver.to_aligned_bytes();
        assert!(WireEnvelope::from_rkyv_bytes(&bad_bin).is_err());
        assert!(WireEnvelope::access_archived(&bad_aligned).is_err());
        assert!(WireEnvelope::view_archived(&bad_aligned).is_err());

        // JSON roundtrip
        let json = env.to_json_string();
        assert_eq!(WireEnvelope::from_json_str(&json), Ok(env));

        // Malformed JSON rejected
        assert!(WireEnvelope::from_json_str("{bad").is_err());

        // Unsupported version in JSON rejected
        let bad_json = bad_ver.to_json_string();
        assert!(WireEnvelope::from_json_str(&bad_json).is_err());
    }

    #[test]
    fn test_wire_frame_header_and_recordio_stream_decoder() {
        let env = WireEnvelope::new(
            100,
            WireMessage::AgentHeartbeat(AgentHeartbeat {
                agent_id: AgentId::new("agent-1").unwrap_or_default(),
                tick: 42,
                healthy_tasks: Vec::new(),
            }),
        );
        // WireFrameHeader roundtrip and all validation error branches
        assert!(WireFrameHeader::new(0, 0, MAX_WIRE_FRAME_BYTES + 1).is_err());
        let hdr = WireFrameHeader::new(1, 3, 256).unwrap_or_default();
        let hdr_bytes = hdr.to_bytes();
        assert_eq!(WireFrameHeader::from_bytes(&hdr_bytes), Ok(hdr));
        assert!(WireFrameHeader::from_bytes(hdr_bytes.get(..8).unwrap_or(&[])).is_err());
        let mut bad_magic = hdr_bytes;
        let _ = bad_magic.first_mut().map(|b| *b = b'X');
        assert!(WireFrameHeader::from_bytes(&bad_magic).is_err());
        let mut bad_crc = hdr_bytes;
        let _ = bad_crc.last_mut().map(|b| *b ^= 0xFF);
        assert!(WireFrameHeader::from_bytes(&bad_crc).is_err());
        let mut bad_ver_hdr = hdr_bytes;
        let _ = bad_ver_hdr
            .get_mut(4..6)
            .map(|s| s.copy_from_slice(&99_u16.to_le_bytes()));
        let bad_ver_crc = compute_wire_crc32(bad_ver_hdr.get(..12).unwrap_or(&[])).to_le_bytes();
        let _ = bad_ver_hdr
            .get_mut(12..16)
            .map(|s| s.copy_from_slice(&bad_ver_crc));
        assert!(WireFrameHeader::from_bytes(&bad_ver_hdr).is_err());
        let mut huge_len_hdr = hdr_bytes;
        let huge_len_bytes = (MAX_WIRE_FRAME_BYTES + 10).to_le_bytes();
        let _ = huge_len_hdr
            .get_mut(8..12)
            .map(|s| s.copy_from_slice(&huge_len_bytes));
        let huge_len_crc = compute_wire_crc32(huge_len_hdr.get(..12).unwrap_or(&[])).to_le_bytes();
        let _ = huge_len_hdr
            .get_mut(12..16)
            .map(|s| s.copy_from_slice(&huge_len_crc));
        assert!(WireFrameHeader::from_bytes(&huge_len_hdr).is_err());
        let _ = rkyv::to_bytes::<rkyv::rancor::Error>(&hdr);

        // RecordIoStreamDecoder incremental chunk feeding and error branches
        let mut dec = RecordIoStreamDecoder::new();
        assert_eq!(dec.buffered_bytes(), 0);
        let f1_str = encode_recordio_frame(&env);
        let split_idx = f1_str.len() / 2;
        let (part1, part2) = f1_str.split_at(split_idx);
        assert_eq!(dec.feed_chunk("1"), Ok(Vec::new()));
        assert!(dec.buffered_bytes() > 0);
        let mut dec2 = RecordIoStreamDecoder::new();
        assert_eq!(dec2.feed_chunk(part1), Ok(Vec::new()));
        assert_eq!(dec2.feed_chunk(part2), Ok(vec![env]));
        assert_eq!(dec2.buffered_bytes(), 0);
        assert!(dec2.feed_chunk("not_a_len\n{}").is_err());
        let mut dec_huge = RecordIoStreamDecoder::new();
        assert!(dec_huge.feed_chunk("999999999\n{}").is_err());
        let mut dec_bad_json = RecordIoStreamDecoder::new();
        assert!(dec_bad_json.feed_chunk("4\n{bad").is_err());
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_recordio_and_all_wire_message_variants() {
        let env = WireEnvelope::new(
            100,
            WireMessage::AgentHeartbeat(AgentHeartbeat {
                agent_id: AgentId::new("agent-1").unwrap_or_default(),
                tick: 42,
                healthy_tasks: vec![TaskId::new("t-1").unwrap_or_default()],
            }),
        );

        // RecordIO framing roundtrip & error branches
        let env2 = WireEnvelope::new(
            101,
            WireMessage::OperatorCall(Box::new(OperatorCall::GetHealth)),
        );
        let f1 = encode_recordio_frame(&env);
        let f2 = encode_recordio_frame(&env2);
        let stream = format!("{f1}{f2}");
        assert_eq!(decode_recordio_frames(&stream), Ok(vec![env, env2]));
        assert_eq!(decode_recordio_frames(""), Ok(Vec::new()));
        assert!(decode_recordio_frames("no-newline").is_err());
        assert!(decode_recordio_frames("abc\n{}").is_err());
        assert!(decode_recordio_frames("9999\n{}").is_err());
        assert!(decode_recordio_frames("4\n{bad").is_err());

        // Exercise rkyv Archive across all WireMessage variants
        let task_spec = TaskSpec {
            task_id: TaskId::default(),
            role: RoleName::default(),
            framework_id: None,
            priority: arbiter_core::workload::PriorityClass::Batch,
            preemption_policy: PreemptionPolicy::ImmediateKill,
            resources: ResourceBundle::zero(),
            required_gpu_vendor: None,
            required_gpu_partition: None,
            topology_constraints: Vec::new(),
            election_group: None,
            isolation: arbiter_core::workload::IsolationSpec {
                capabilities: Vec::new(),
                image_ref: None,
                command: String::new(),
                args: Vec::new(),
                env: Vec::new(),
                run_as_user: None,
            },
            artifacts: Vec::new(),
            secrets: Vec::new(),
            health_check: None,
        };
        let all_messages = vec![
            WireMessage::RegisterAgent(Box::new(RegisterAgent {
                agent_id: AgentId::default(),
                os_kind: OsKind::Linux,
                cpu_arch: CpuArch::X86_64,
                total_resources: ResourceBundle::zero(),
                topology: HardwareTopologyGraph::new(),
            })),
            WireMessage::AgentHeartbeat(AgentHeartbeat {
                agent_id: AgentId::default(),
                tick: 1,
                healthy_tasks: Vec::new(),
            }),
            WireMessage::HardwareTelemetryReport(HardwareTelemetryReport {
                agent_id: AgentId::default(),
                allocated_resources: ResourceBundle::zero(),
                max_temperature: TemperatureMilliCelsius::default(),
                total_power: PowerMilliwatts::ZERO,
            }),
            WireMessage::LaunchTaskCommand(Box::new(LaunchTaskCommand {
                agent_id: AgentId::default(),
                task: task_spec.clone(),
            })),
            WireMessage::PreemptTaskCommand(PreemptTaskCommand {
                agent_id: AgentId::default(),
                task_id: TaskId::default(),
                policy: PreemptionPolicy::ImmediateKill,
            }),
            WireMessage::TaskStatusUpdate(TaskStatusUpdate {
                task_id: TaskId::default(),
                agent_id: AgentId::default(),
                state: TaskState::Running,
                message: String::new(),
            }),
            WireMessage::SubscribeFramework(SubscribeFramework {
                framework_id: FrameworkId::default(),
                role: RoleName::default(),
                failover_timeout_ms: 0,
            }),
            WireMessage::ResourceOfferBatch(ResourceOfferBatch {
                framework_id: FrameworkId::default(),
                offers: Vec::new(),
            }),
            WireMessage::AcceptOffers(AcceptOffers {
                framework_id: FrameworkId::default(),
                offer_ids: Vec::new(),
                operations: Vec::new(),
            }),
            WireMessage::SubmitDirectJob(SubmitDirectJob::SingleTask(Box::new(task_spec))),
            WireMessage::SchedulerCall(Box::new(SchedulerCall::Subscribe(
                SubscribeFramework {
                    framework_id: FrameworkId::default(),
                    role: RoleName::default(),
                    failover_timeout_ms: 0,
                },
                CheckpointMode::Enabled,
                Vec::new(),
                Vec::new(),
            ))),
            WireMessage::SchedulerEvent(Box::new(SchedulerEvent::Subscribed(
                FrameworkId::new("a").unwrap_or_default(),
                MasterInfo {
                    leader_id: "a".to_owned(),
                    version: "a".to_owned(),
                    elected_term: 1,
                },
                BenchmarkTicks::new(1),
            ))),
            WireMessage::ExecutorCall(Box::new(ExecutorCall::Subscribe(
                FrameworkId::new("a").unwrap_or_default(),
                ExecutorId::new("a").unwrap_or_default(),
                Vec::new(),
                Vec::new(),
            ))),
            WireMessage::ExecutorEvent(Box::new(ExecutorEvent::Subscribed(ExecutorInfo {
                executor_id: ExecutorId::new("a").unwrap_or_default(),
                agent_id: AgentId::new("a").unwrap_or_default(),
            }))),
            WireMessage::OperatorCall(Box::new(OperatorCall::UpdateWeights(Vec::new()))),
            WireMessage::OperatorResponse(Box::new(OperatorResponse::Health(true))),
            WireMessage::OperatorEvent(OperatorEvent::TaskAdded(
                TaskId::new("a").unwrap_or_default(),
                AgentId::new("a").unwrap_or_default(),
            )),
            WireMessage::ResourceProviderCall(Box::new(ResourceProviderCall::Subscribe(
                ResourceProviderInfo {
                    provider_id: ResourceProviderId::new("a").unwrap_or_default(),
                    agent_id: None,
                    provider_type: "a".to_owned(),
                    provider_name: "a".to_owned(),
                    default_role: RoleName::new("a").unwrap_or_default(),
                    advertised_disks: Vec::new(),
                },
            ))),
            WireMessage::ResourceProviderEvent(Box::new(ResourceProviderEvent::Subscribed(
                ResourceProviderId::new("a").unwrap_or_default(),
            ))),
            WireMessage::AgentOperatorCall(Box::new(AgentOperatorCall::GetContainers)),
            WireMessage::AgentOperatorCall(Box::new(AgentOperatorCall::LaunchNestedContainer(
                ContainerId::new("c1").unwrap_or_default(),
                ContainerId::new("c1.nested").unwrap_or_default(),
                "/bin/sh".to_owned(),
                vec!["-c".to_owned()],
                vec![("K".to_owned(), "V".to_owned())],
                ResourceBundle::zero(),
            ))),
            WireMessage::AgentOperatorCall(Box::new(AgentOperatorCall::WaitNestedContainer(
                ContainerId::new("c1.nested").unwrap_or_default(),
            ))),
            WireMessage::AgentOperatorCall(Box::new(AgentOperatorCall::KillNestedContainer(
                ContainerId::new("c1.nested").unwrap_or_default(),
                SignalNumber::SIGTERM,
            ))),
            WireMessage::AgentOperatorCall(Box::new(AgentOperatorCall::RemoveNestedContainer(
                ContainerId::new("c1.nested").unwrap_or_default(),
            ))),
            WireMessage::AgentOperatorCall(Box::new(
                AgentOperatorCall::LaunchNestedContainerSession(
                    ContainerId::new("c1").unwrap_or_default(),
                    ContainerId::new("c1.sess").unwrap_or_default(),
                    "/bin/sh".to_owned(),
                    Vec::new(),
                ),
            )),
            WireMessage::AgentOperatorCall(Box::new(AgentOperatorCall::AttachContainerInput(
                ContainerId::new("c1.sess").unwrap_or_default(),
                b"ls\n".to_vec(),
            ))),
            WireMessage::AgentOperatorCall(Box::new(AgentOperatorCall::AttachContainerOutput(
                ContainerId::new("c1.sess").unwrap_or_default(),
            ))),
            WireMessage::AgentOperatorCall(Box::new(AgentOperatorCall::PruneImages(vec![
                "alpine:latest".to_owned(),
            ]))),
            WireMessage::AgentOperatorResponse(Box::new(AgentOperatorResponse::Containers(vec![
                ContainerStatusInfo {
                    container_id: ContainerId::new("c1").unwrap_or_default(),
                    parent_container_id: Some(ContainerId::new("p1").unwrap_or_default()),
                    executor_id: ExecutorId::new("e1").unwrap_or_default(),
                    allocated_resources: ResourceBundle::zero(),
                    running: true,
                    exit_status: Some(ExitCode::SUCCESS),
                },
            ]))),
            WireMessage::AgentOperatorResponse(Box::new(
                AgentOperatorResponse::NestedContainerWaitResult(
                    ContainerId::new("c1.nested").unwrap_or_default(),
                    ExitCode::SUCCESS,
                ),
            )),
            WireMessage::AgentOperatorResponse(Box::new(
                AgentOperatorResponse::ContainerOutputChunk(
                    ContainerId::new("c1.sess").unwrap_or_default(),
                    b"out".to_vec(),
                    b"err".to_vec(),
                ),
            )),
            WireMessage::AgentOperatorResponse(Box::new(AgentOperatorResponse::ImagesPruned(
                2,
                Bytes::new(4096),
            ))),
            WireMessage::AgentOperatorResponse(Box::new(AgentOperatorResponse::Ok(
                "ok".to_owned(),
            ))),
            WireMessage::RaftRpc(Box::new(RaftRpcMessage::RequestVote(
                1,
                "a".to_owned(),
                0,
                0,
            ))),
        ];
        for msg in all_messages {
            let e = WireEnvelope::new(1, msg);
            let bytes = e.to_rkyv_bytes();
            let summary = WireEnvelope::inspect_framed_header_zero_copy(&bytes);
            assert!(summary.is_ok());
            assert_eq!(WireEnvelope::from_rkyv_bytes(&bytes), Ok(e));
            for i in 0..bytes.len() {
                let mut corrupted = bytes.clone();
                for (j, b) in corrupted.iter_mut().enumerate() {
                    if i == j {
                        *b ^= 0xFF;
                    }
                }
                let _ = WireEnvelope::from_rkyv_bytes(&corrupted);
                let _ = WireEnvelope::inspect_framed_header_zero_copy(&corrupted);
            }
        }
        assert_eq!(
            WireCodecContentType::default(),
            WireCodecContentType::ApplicationJson
        );
        for (hdr, expected, mime) in [
            (
                "application/json; charset=utf-8",
                WireCodecContentType::ApplicationJson,
                "application/json",
            ),
            (
                "application/x-protobuf",
                WireCodecContentType::ApplicationProtobuf,
                "application/x-protobuf",
            ),
            (
                "application/x-rkyv",
                WireCodecContentType::ApplicationRkyv,
                "application/x-rkyv",
            ),
        ] {
            let ct = std::hint::black_box(WireCodecContentType::from_content_type_header(hdr));
            assert_eq!(ct, expected);
            assert_eq!(std::hint::black_box(ct.as_mime_str()), mime);
        }
    }

    proptest! {
        #[test]
        fn prop_heartbeat_rkyv_and_json_roundtrip(seq in 1..10_000_u64, tick in 0..1_000_000_u64) {
            let env = WireEnvelope::new(
                seq,
                WireMessage::AgentHeartbeat(AgentHeartbeat {
                    agent_id: AgentId::new("agent-prop").unwrap_or_default(),
                    tick,
                    healthy_tasks: Vec::new(),
                }),
            );
            let bin = env.to_rkyv_bytes();
            prop_assert_eq!(WireEnvelope::from_rkyv_bytes(&bin), Ok(env.clone()));

            let json = env.to_json_string();
            prop_assert_eq!(WireEnvelope::from_json_str(&json), Ok(env));
        }
    }

    proptest! {
        #[test]
        fn prop_fuzz_rkyv_and_json_never_panic(random_bytes in proptest::collection::vec(any::<u8>(), 0..128)) {
            let _ = WireEnvelope::from_rkyv_bytes(&random_bytes);
            if let Ok(s) = core::str::from_utf8(&random_bytes) {
                let _ = WireEnvelope::from_json_str(s);
            }
        }
    }
}
