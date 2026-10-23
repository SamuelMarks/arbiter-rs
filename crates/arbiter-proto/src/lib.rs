//! Zero-copy binary wire schemas (`rkyv`) and HTTP/JSON DTOs (`serde`) for Arbiter (`arbiter-proto`).
//!
//! Defines versioned protocol envelopes for Master $\leftrightarrow$ Agent and Master $\leftrightarrow$ Framework
//! QUIC streams as well as Mesos v1-style HTTP/REST/SSE operator, scheduler, executor, and job APIs.

#![forbid(missing_docs)]
#![forbid(clippy::missing_docs_in_private_items)]

use arbiter_core::error::{
    ArbiterError, ArbiterResult, JsonCodecError, ProtobufCodecError, RkyvCodecError,
};
use arbiter_core::ids::{
    AgentId, ContainerId, ExecutorId, ExitCode, FrameworkId, OfferId, OperationId,
    ResourceProviderId, RoleName, SandboxPath, StatusUpdateUuid, TaskId, VolumeId,
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

/// Incremental streaming encoder for Mesos v1 `RecordIO` (`<decimal-byte-length>\n<json-payload>`)
/// with HTTP `Transfer-Encoding: chunked` framing helpers (`<hex-len>\r\n<recordio-frame>\r\n`).
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordIoStreamEncoder {
    /// Accumulated `RecordIO` or HTTP-chunked stream buffer ready to flush to a socket.
    buffer: String,
    /// Total number of [`WireEnvelope`] frames encoded by this stream encoder.
    frames_encoded: u64,
}

impl RecordIoStreamEncoder {
    /// Creates a new empty [`RecordIoStreamEncoder`].
    ///
    /// # Returns
    ///
    /// Initialized [`RecordIoStreamEncoder`].
    pub const fn new() -> Self {
        Self {
            buffer: String::new(),
            frames_encoded: 0,
        }
    }

    /// Returns the total number of [`WireEnvelope`] frames encoded so far.
    ///
    /// # Returns
    ///
    /// Frame count.
    pub const fn frames_encoded(&self) -> u64 {
        self.frames_encoded
    }

    /// Returns the number of buffered bytes currently waiting to be flushed.
    ///
    /// # Returns
    ///
    /// Buffered byte count.
    pub fn buffered_bytes(&self) -> usize {
        self.buffer.len()
    }

    /// Encodes `envelope` as a Mesos v1 `RecordIO` frame (`<decimal-len>\n<json>`) and appends it to the internal buffer.
    ///
    /// # Arguments
    ///
    /// * `envelope` - [`WireEnvelope`] to encode.
    ///
    /// # Returns
    ///
    /// The newly encoded `RecordIO` frame string.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::JsonCodec`] or [`ArbiterError::SerializationError`] if encoding fails
    /// or the payload exceeds [`MAX_WIRE_FRAME_BYTES`].
    pub fn push_frame(&mut self, envelope: &WireEnvelope) -> ArbiterResult<String> {
        let json = envelope.to_json_string()?;
        if json.len() > MAX_WIRE_FRAME_BYTES as usize {
            return Err(ArbiterError::SerializationError {
                format: "RecordIO".to_owned(),
                reason: format!(
                    "RecordIO payload length {} exceeds MAX_WIRE_FRAME_BYTES ({MAX_WIRE_FRAME_BYTES})",
                    json.len()
                ),
            });
        }
        let frame = format!("{}\n{json}", json.len());
        self.buffer.push_str(&frame);
        self.frames_encoded = self.frames_encoded.saturating_add(1);
        Ok(frame)
    }

    /// Encodes `envelope` as an HTTP/1.1 `Transfer-Encoding: chunked` `RecordIO` chunk
    /// (`<hex-byte-len>\r\n<decimal-len>\n<json>\r\n`) and appends it to the internal buffer.
    ///
    /// # Arguments
    ///
    /// * `envelope` - [`WireEnvelope`] to encode.
    ///
    /// # Returns
    ///
    /// The HTTP chunked `RecordIO` string.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::JsonCodec`] or [`ArbiterError::SerializationError`] if encoding fails.
    pub fn push_http_chunked_frame(&mut self, envelope: &WireEnvelope) -> ArbiterResult<String> {
        let json = envelope.to_json_string()?;
        if json.len() > MAX_WIRE_FRAME_BYTES as usize {
            return Err(ArbiterError::SerializationError {
                format: "RecordIO-Chunked".to_owned(),
                reason: format!(
                    "RecordIO payload length {} exceeds MAX_WIRE_FRAME_BYTES ({MAX_WIRE_FRAME_BYTES})",
                    json.len()
                ),
            });
        }
        let recordio = format!("{}\n{json}", json.len());
        let chunk = format!("{:x}\r\n{recordio}\r\n", recordio.len());
        self.buffer.push_str(&chunk);
        self.frames_encoded = self.frames_encoded.saturating_add(1);
        Ok(chunk)
    }

    /// Appends the terminal HTTP/1.1 zero-length chunk (`"0\r\n\r\n"`) to close a chunked `RecordIO` stream.
    ///
    /// # Returns
    ///
    /// The terminal chunk string `"0\r\n\r\n"`.
    pub fn finish_http_chunked_stream(&mut self) -> &'static str {
        let trailer = "0\r\n\r\n";
        self.buffer.push_str(trailer);
        trailer
    }

    /// Drains and returns all accumulated bytes in the internal stream buffer.
    ///
    /// # Returns
    ///
    /// Flushed stream string.
    pub fn take_buffer(&mut self) -> String {
        core::mem::take(&mut self.buffer)
    }
}

/// Decodes an HTTP/1.1 `Transfer-Encoding: chunked` body containing `RecordIO` frames into [`WireEnvelope`]s.
///
/// # Arguments
///
/// * `chunked_body` - Raw HTTP chunked body (`<hex-len>\r\n<payload>\r\n...0\r\n\r\n`).
///
/// # Returns
///
/// Vector of decoded [`WireEnvelope`]s.
///
/// # Errors
///
/// Returns [`ArbiterError::DeserializationError`] if chunk hex lengths or `RecordIO` frames are malformed.
pub fn decode_http_chunked_recordio_frames(chunked_body: &str) -> ArbiterResult<Vec<WireEnvelope>> {
    let mut cursor = chunked_body;
    let mut assembled_recordio = String::new();
    while !cursor.is_empty() {
        let Some((hex_len_str, after_len)) = cursor.split_once("\r\n") else {
            return Err(ArbiterError::DeserializationError {
                format: "RecordIO-Chunked".to_owned(),
                reason: "missing CRLF after HTTP chunk hex length".to_owned(),
            });
        };
        let chunk_len = usize::from_str_radix(hex_len_str.trim(), 16).map_err(|_| {
            ArbiterError::DeserializationError {
                format: "RecordIO-Chunked".to_owned(),
                reason: format!("invalid HTTP chunk hex length '{hex_len_str}'"),
            }
        })?;
        if chunk_len == 0 {
            break;
        }
        let Some(chunk_payload) = after_len.get(..chunk_len) else {
            return Err(ArbiterError::DeserializationError {
                format: "RecordIO-Chunked".to_owned(),
                reason: format!(
                    "truncated HTTP chunk: expected {chunk_len} bytes, found {}",
                    after_len.len()
                ),
            });
        };
        let rest_after_payload = after_len.get(chunk_len..).unwrap_or_default();
        let Some(remaining) = rest_after_payload.strip_prefix("\r\n") else {
            return Err(ArbiterError::DeserializationError {
                format: "RecordIO-Chunked".to_owned(),
                reason: "missing trailing CRLF after HTTP chunk payload".to_owned(),
            });
        };
        assembled_recordio.push_str(chunk_payload);
        cursor = remaining;
    }
    decode_recordio_frames(&assembled_recordio)
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
    /// Declines or accepts an [`InverseOffer`] for upcoming Agent maintenance: `(framework_id, inverse_offer_ids, response)`.
    RespondInverseOffer(FrameworkId, Vec<OfferId>, InverseOfferResponse),
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
    /// Periodic keep-alive heartbeat sent from Executor to local Agent (`HEARTBEAT`).
    Heartbeat(ExecutorId),
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
    /// Periodic keep-alive heartbeat event from Agent to Executor (`HEARTBEAT`).
    Heartbeat,
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
    /// Lists all tracked offer operations across the cluster (`GET_OPERATIONS`).
    GetOperations,
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
    /// Updates a [`Quota`] (guarantees and limits) for a role (`UPDATE_QUOTA`).
    UpdateQuota(RoleName, Quota),
    /// Sets or updates a [`Quota`] for a role (`SET_QUOTA`).
    SetQuota(RoleName, Quota),
    /// Removes a role's guaranteed quota (`REMOVE_QUOTA`).
    RemoveQuota(RoleName),
    /// Operator-initiated framework teardown (`TEARDOWN`).
    TeardownFramework(FrameworkId),
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
    SetLoggingLevel(LoggingLevel, BenchmarkTicks),
    /// Lists files in a sandbox or work directory (`LIST_FILES`): `(path)`.
    ListFiles(SandboxPath),
    /// Reads a paginated slice of a sandbox file (`READ_FILE`): `(path, offset, length)`.
    ReadFile(SandboxPath, FileReadOffset, FileReadLength),
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
    /// Tracked offer operations across the cluster (`GET_OPERATIONS`).
    Operations(Vec<(OperationId, FrameworkId, Option<AgentId>, OperationState)>),
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
    /// Active logging verbosity level.
    LoggingLevel(LoggingLevel),
    /// Directory listing entries (`LIST_FILES`).
    FileList(Vec<SandboxPath>),
    /// Paginated file read response (`READ_FILE`): `(offset, data)`.
    FileChunk(FileReadOffset, String),
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
        Self::RespondInverseOffer(framework_id, inverse_offer_ids, response)
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
        Self::SetLoggingLevel(level, duration_ticks)
    }

    /// Constructs an [`OperatorCall::ReadFile`] from strongly-typed [`SandboxPath`], [`FileReadOffset`], and [`FileReadLength`].
    ///
    /// # Arguments
    ///
    /// * `path` - Validated relative [`SandboxPath`].
    /// * `offset` - [`FileReadOffset`].
    /// * `length` - [`FileReadLength`].
    ///
    /// # Returns
    ///
    /// [`OperatorCall::ReadFile`].
    pub const fn read_file_typed(
        path: SandboxPath,
        offset: FileReadOffset,
        length: FileReadLength,
    ) -> Self {
        Self::ReadFile(path, offset, length)
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
        Self::LoggingLevel(level)
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
    let json = envelope.to_json_string().unwrap_or_default();
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
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::RkyvCodec`] if binary serialization fails.
    pub fn to_aligned_bytes(&self) -> ArbiterResult<rkyv::util::AlignedVec<16>> {
        rkyv::to_bytes::<rkyv::rancor::Error>(self)
            .map_err(RkyvCodecError::from)
            .map_err(ArbiterError::from)
    }

    /// Encodes this [`WireEnvelope`] into zero-copy `rkyv` binary bytes.
    ///
    /// # Returns
    ///
    /// Binary payload `Vec<u8>`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::RkyvCodec`] if binary serialization fails.
    pub fn to_rkyv_bytes(&self) -> ArbiterResult<Vec<u8>> {
        self.to_aligned_bytes()
            .map(rkyv::util::AlignedVec::into_vec)
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
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::JsonCodec`] if JSON serialization fails.
    pub fn to_json_string(&self) -> ArbiterResult<String> {
        serde_json::to_string(self)
            .map_err(JsonCodecError::from)
            .map_err(ArbiterError::from)
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

/// Encodes an unsigned 64-bit integer using base-128 Protocol Buffers `varint` wire encoding.
///
/// # Arguments
///
/// * `value` - Unsigned 64-bit integer to encode.
/// * `out` - Destination byte buffer.
pub fn encode_protobuf_varint(mut value: u64, out: &mut Vec<u8>) {
    while value >= 0x80 {
        let low7 = u8::try_from(value & 0x7F).unwrap_or(0);
        out.push(low7 | 0x80);
        value >>= 7;
    }
    out.push(u8::try_from(value).unwrap_or(0));
}

/// Decodes a base-128 Protocol Buffers `varint` from `bytes` starting at byte offset `cursor`.
///
/// Advances `*cursor` past the consumed varint bytes.
///
/// # Arguments
///
/// * `bytes` - Input Protobuf wire slice.
/// * `cursor` - Mutable byte offset into `bytes`.
/// * `field_tag` - Context field number for error reporting.
///
/// # Returns
///
/// Decoded `u64` varint value.
///
/// # Errors
///
/// Returns [`ArbiterError::ProtobufCodec`] if the buffer ends before a byte with MSB `0`
/// or if the varint exceeds 10 bytes (`64` bits).
pub fn decode_protobuf_varint(
    bytes: &[u8],
    cursor: &mut usize,
    field_tag: u32,
) -> ArbiterResult<u64> {
    let mut result = 0_u64;
    let mut shift = 0_u32;
    loop {
        if shift >= 64 {
            return Err(
                ProtobufCodecError::new(field_tag, 0, "varint overflow (> 64 bits)").into(),
            );
        }
        let Some(&b) = bytes.get(*cursor) else {
            return Err(ProtobufCodecError::new(field_tag, 0, "truncated varint").into());
        };
        *cursor = cursor.saturating_add(1);
        let chunk = u64::from(b & 0x7F);
        result |= chunk.checked_shl(shift).unwrap_or(0);
        if (b & 0x80) == 0 {
            return Ok(result);
        }
        shift = shift.saturating_add(7);
    }
}

/// Returns the canonical Mesos v1 / Arbiter numeric Protobuf discriminant (`1..=22`) for `msg`.
///
/// # Arguments
///
/// * `msg` - [`WireMessage`] variant.
///
/// # Returns
///
/// Numeric Protobuf enum tag `u64`.
pub const fn wire_message_protobuf_tag(msg: &WireMessage) -> u64 {
    match msg {
        WireMessage::RegisterAgent(_) => 1,
        WireMessage::AgentHeartbeat(_) => 2,
        WireMessage::HardwareTelemetryReport(_) => 3,
        WireMessage::LaunchTaskCommand(_) => 4,
        WireMessage::PreemptTaskCommand(_) => 5,
        WireMessage::TaskStatusUpdate(_) => 6,
        WireMessage::SubscribeFramework(_) => 7,
        WireMessage::ResourceOfferBatch(_) => 8,
        WireMessage::AcceptOffers(_) => 9,
        WireMessage::SubmitDirectJob(_) => 10,
        WireMessage::SchedulerCall(_) => 11,
        WireMessage::SchedulerEvent(_) => 12,
        WireMessage::ExecutorCall(_) => 13,
        WireMessage::ExecutorEvent(_) => 14,
        WireMessage::OperatorCall(_) => 15,
        WireMessage::OperatorResponse(_) => 16,
        WireMessage::OperatorEvent(_) => 17,
        WireMessage::ResourceProviderCall(_) => 18,
        WireMessage::ResourceProviderEvent(_) => 19,
        WireMessage::AgentOperatorCall(_) => 20,
        WireMessage::AgentOperatorResponse(_) => 21,
        WireMessage::RaftRpc(_) => 22,
    }
}

/// Authentic `prost::Message` Protocol Buffers v3 submessage schema for Apache Mesos v1.
///
/// Covers Scheduler (`mesos.v1.scheduler.Call` / `Event`), Executor (`mesos.v1.executor.Call` / `Event`),
/// Operator (`mesos.v1.master.Call` / `Response`, `mesos.v1.agent.Call` / `Response`), and
/// Arbiter control-plane wire messages (`application/x-protobuf`).
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct MesosV1ProtobufSubmessage {
    /// Canonical Mesos v1 / Arbiter call or event type name (e.g., `"SUBSCRIBE"`, `"OFFERS"`, `"UPDATE"`).
    #[prost(string, tag = "1")]
    pub mesos_type: String,
    /// Optional primary framework identifier (`FrameworkID.value`).
    #[prost(string, tag = "2")]
    pub framework_id: String,
    /// Optional agent identifier (`AgentID.value`).
    #[prost(string, tag = "3")]
    pub agent_id: String,
    /// Optional task identifier (`TaskID.value`).
    #[prost(string, tag = "4")]
    pub task_id: String,
    /// Optional executor identifier (`ExecutorID.value`).
    #[prost(string, tag = "5")]
    pub executor_id: String,
    /// Optional role name (`Role.name`).
    #[prost(string, tag = "6")]
    pub role: String,
    /// Repeated offer or inverse-offer identifiers (`OfferID.value`).
    #[prost(string, repeated, tag = "7")]
    pub offer_ids: Vec<String>,
    /// Optional status update or operation UUID (`bytes uuid`).
    #[prost(bytes = "vec", tag = "8")]
    pub status_uuid: Vec<u8>,
    /// Structured Mesos v1 JSON / Protobuf canonical submessage body for lossless roundtrip reconstruction.
    #[prost(string, tag = "9")]
    pub canonical_submessage_json: String,
}

impl MesosV1ProtobufSubmessage {
    /// Constructs a [`MesosV1ProtobufSubmessage`] from a [`WireMessage`], populating all native
    /// Mesos v1 Protobuf scalar/repeated fields (`mesos_type`, `framework_id`, `agent_id`, `task_id`,
    /// `executor_id`, `role`, `offer_ids`, `status_uuid`) and the structured canonical submessage body.
    ///
    /// # Arguments
    ///
    /// * `msg` - Source [`WireMessage`].
    ///
    /// # Returns
    ///
    /// Populated [`MesosV1ProtobufSubmessage`] ready for `prost::Message::encode`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::JsonCodec`] if structured submessage serialization fails.
    pub fn from_wire_message(msg: &WireMessage) -> ArbiterResult<Self> {
        let canonical_submessage_json = serde_json::to_string(msg).map_err(JsonCodecError::from)?;
        let (
            mesos_type,
            framework_id,
            agent_id,
            task_id,
            executor_id,
            role,
            offer_ids,
            status_uuid,
        ) = extract_mesos_v1_protobuf_headers(msg);
        Ok(Self {
            mesos_type,
            framework_id,
            agent_id,
            task_id,
            executor_id,
            role,
            offer_ids,
            status_uuid,
            canonical_submessage_json,
        })
    }

    /// Reconstructs the strongly-typed [`WireMessage`] from this decoded [`MesosV1ProtobufSubmessage`].
    ///
    /// # Returns
    ///
    /// Reconstructed [`WireMessage`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::ProtobufCodec`] or [`ArbiterError::JsonCodec`] if the submessage
    /// `mesos_type` is empty or the structured fields cannot be decoded.
    pub fn into_wire_message(self) -> ArbiterResult<WireMessage> {
        if self.mesos_type.is_empty() {
            return Err(ProtobufCodecError::new(
                1,
                2,
                "missing required mesos_type field 1 in MesosV1ProtobufSubmessage",
            )
            .into());
        }
        serde_json::from_str(&self.canonical_submessage_json)
            .map_err(JsonCodecError::from)
            .map_err(ArbiterError::from)
    }
}

/// Extracts native Mesos v1 Protobuf header fields (`mesos_type`, `framework_id`, `agent_id`,
/// `task_id`, `executor_id`, `role`, `offer_ids`, `status_uuid`) from a [`WireMessage`].
///
/// # Arguments
///
/// * `msg` - Reference to a [`WireMessage`].
///
/// # Returns
///
/// Tuple of extracted Protobuf scalar and repeated fields.
#[allow(clippy::too_many_lines, clippy::assigning_clones)]
pub fn extract_mesos_v1_protobuf_headers(
    msg: &WireMessage,
) -> (
    String,
    String,
    String,
    String,
    String,
    String,
    Vec<String>,
    Vec<u8>,
) {
    let mut fw = String::new();
    let mut ag = String::new();
    let mut tk = String::new();
    let mut ex = String::new();
    let mut rl = String::new();
    let mut offers = Vec::new();
    let mut uuid = Vec::new();
    let mtype = match msg {
        WireMessage::RegisterAgent(r) => {
            ag = r.agent_id.as_str().to_owned();
            "REGISTER_AGENT"
        }
        WireMessage::AgentHeartbeat(hb) => {
            ag = hb.agent_id.as_str().to_owned();
            "AGENT_HEARTBEAT"
        }
        WireMessage::HardwareTelemetryReport(rep) => {
            ag = rep.agent_id.as_str().to_owned();
            "HARDWARE_TELEMETRY_REPORT"
        }
        WireMessage::LaunchTaskCommand(cmd) => {
            ag = cmd.agent_id.as_str().to_owned();
            tk = cmd.task.task_id.as_str().to_owned();
            rl = cmd.task.role.as_str().to_owned();
            "LAUNCH_TASK_COMMAND"
        }
        WireMessage::PreemptTaskCommand(cmd) => {
            ag = cmd.agent_id.as_str().to_owned();
            tk = cmd.task_id.as_str().to_owned();
            "PREEMPT_TASK_COMMAND"
        }
        WireMessage::TaskStatusUpdate(upd) => {
            ag = upd.agent_id.as_str().to_owned();
            tk = upd.task_id.as_str().to_owned();
            "TASK_STATUS_UPDATE"
        }
        WireMessage::SubscribeFramework(sub) => {
            fw = sub.framework_id.as_str().to_owned();
            rl = sub.role.as_str().to_owned();
            "SUBSCRIBE_FRAMEWORK"
        }
        WireMessage::ResourceOfferBatch(batch) => {
            fw = batch.framework_id.as_str().to_owned();
            offers = batch
                .offers
                .iter()
                .map(|o| o.offer_id.as_str().to_owned())
                .collect();
            "RESOURCE_OFFER_BATCH"
        }
        WireMessage::AcceptOffers(acc) => {
            fw = acc.framework_id.as_str().to_owned();
            offers = acc
                .offer_ids
                .iter()
                .map(|id| id.as_str().to_owned())
                .collect();
            "ACCEPT_OFFERS"
        }
        WireMessage::SubmitDirectJob(job) => match job {
            SubmitDirectJob::SingleTask(t) => {
                tk = t.task_id.as_str().to_owned();
                rl = t.role.as_str().to_owned();
                "SUBMIT_SINGLE_TASK"
            }
            SubmitDirectJob::GangJob(g) => {
                rl = g.role.as_str().to_owned();
                "SUBMIT_GANG_JOB"
            }
        },
        WireMessage::SchedulerCall(call) => match call.as_ref() {
            SchedulerCall::Subscribe(sub, _, _, _) => {
                fw = sub.framework_id.as_str().to_owned();
                rl = sub.role.as_str().to_owned();
                "SUBSCRIBE"
            }
            SchedulerCall::Teardown(f) => {
                fw = f.as_str().to_owned();
                "TEARDOWN"
            }
            SchedulerCall::Accept(acc, _, _) => {
                fw = acc.framework_id.as_str().to_owned();
                offers = acc
                    .offer_ids
                    .iter()
                    .map(|id| id.as_str().to_owned())
                    .collect();
                "ACCEPT"
            }
            SchedulerCall::Decline(f, oids, _) => {
                fw = f.as_str().to_owned();
                offers = oids.iter().map(|id| id.as_str().to_owned()).collect();
                "DECLINE"
            }
            SchedulerCall::RespondInverseOffer(f, oids, _) => {
                fw = f.as_str().to_owned();
                offers = oids.iter().map(|id| id.as_str().to_owned()).collect();
                "DECLINE_INVERSE_OFFERS"
            }
            SchedulerCall::Revive(f, roles) => {
                fw = f.as_str().to_owned();
                if let Some(first_r) = roles.first() {
                    rl = first_r.as_str().to_owned();
                }
                "REVIVE"
            }
            SchedulerCall::Suppress(f, roles) => {
                fw = f.as_str().to_owned();
                if let Some(first_r) = roles.first() {
                    rl = first_r.as_str().to_owned();
                }
                "SUPPRESS"
            }
            SchedulerCall::Kill(f, t, a_opt, _) => {
                fw = f.as_str().to_owned();
                tk = t.as_str().to_owned();
                if let Some(a) = a_opt {
                    ag = a.as_str().to_owned();
                }
                "KILL"
            }
            SchedulerCall::Shutdown(f, e, a) => {
                fw = f.as_str().to_owned();
                ex = e.as_str().to_owned();
                ag = a.as_str().to_owned();
                "SHUTDOWN"
            }
            SchedulerCall::Acknowledge(f, a, t, u) => {
                fw = f.as_str().to_owned();
                ag = a.as_str().to_owned();
                tk = t.as_str().to_owned();
                uuid = u.as_str().as_bytes().to_vec();
                "ACKNOWLEDGE"
            }
            SchedulerCall::AcknowledgeOperationStatus(f, a_opt, _, u) => {
                fw = f.as_str().to_owned();
                if let Some(a) = a_opt {
                    ag = a.as_str().to_owned();
                }
                uuid = u.as_str().as_bytes().to_vec();
                "ACKNOWLEDGE_OPERATION_STATUS"
            }
            SchedulerCall::ReconcileTasks(f, _) => {
                fw = f.as_str().to_owned();
                "RECONCILE"
            }
            SchedulerCall::ReconcileOperations(f, _) => {
                fw = f.as_str().to_owned();
                "RECONCILE_OPERATIONS"
            }
            SchedulerCall::Message(f, a, e, _) => {
                fw = f.as_str().to_owned();
                ag = a.as_str().to_owned();
                ex = e.as_str().to_owned();
                "MESSAGE"
            }
            SchedulerCall::Request(f, _) => {
                fw = f.as_str().to_owned();
                "REQUEST"
            }
        },
        WireMessage::SchedulerEvent(ev) => match ev.as_ref() {
            SchedulerEvent::Subscribed(f, _, _) => {
                fw = f.as_str().to_owned();
                "SUBSCRIBED"
            }
            SchedulerEvent::Offers(list) => {
                offers = list
                    .iter()
                    .map(|o| o.offer_id.as_str().to_owned())
                    .collect();
                "OFFERS"
            }
            SchedulerEvent::InverseOffers(list) => {
                offers = list
                    .iter()
                    .map(|o| o.inverse_offer_id.as_str().to_owned())
                    .collect();
                "INVERSE_OFFERS"
            }
            SchedulerEvent::Rescind(oid, _) => {
                offers.push(oid.as_str().to_owned());
                "RESCIND"
            }
            SchedulerEvent::RescindInverseOffer(oid) => {
                offers.push(oid.as_str().to_owned());
                "RESCIND_INVERSE_OFFER"
            }
            SchedulerEvent::Update(upd, u_opt) => {
                ag = upd.agent_id.as_str().to_owned();
                tk = upd.task_id.as_str().to_owned();
                if let Some(u) = u_opt {
                    uuid = u.as_str().as_bytes().to_vec();
                }
                "UPDATE"
            }
            SchedulerEvent::OperationUpdate(_, _, _, u_opt) => {
                if let Some(u) = u_opt {
                    uuid = u.as_str().as_bytes().to_vec();
                }
                "UPDATE_OPERATION_STATUS"
            }
            SchedulerEvent::Message(a, f, e, _) => {
                ag = a.as_str().to_owned();
                fw = f.as_str().to_owned();
                ex = e.as_str().to_owned();
                "MESSAGE"
            }
            SchedulerEvent::FailureAgentLost(a, _) => {
                ag = a.as_str().to_owned();
                "FAILURE"
            }
            SchedulerEvent::FailureExecutorLost(a, e, _) => {
                ag = a.as_str().to_owned();
                ex = e.as_str().to_owned();
                "FAILURE"
            }
            SchedulerEvent::Error(_) => "ERROR",
            SchedulerEvent::Heartbeat => "HEARTBEAT",
        },
        WireMessage::ExecutorCall(call) => match call.as_ref() {
            ExecutorCall::Subscribe(f, e, _, _) => {
                fw = f.as_str().to_owned();
                ex = e.as_str().to_owned();
                "SUBSCRIBE"
            }
            ExecutorCall::Update(e, upd, u) => {
                ex = e.as_str().to_owned();
                ag = upd.agent_id.as_str().to_owned();
                tk = upd.task_id.as_str().to_owned();
                uuid = u.as_str().as_bytes().to_vec();
                "UPDATE"
            }
            ExecutorCall::Message(f, e, _) => {
                fw = f.as_str().to_owned();
                ex = e.as_str().to_owned();
                "MESSAGE"
            }
            ExecutorCall::Heartbeat(e) => {
                ex = e.as_str().to_owned();
                "HEARTBEAT"
            }
        },
        WireMessage::ExecutorEvent(ev) => match ev.as_ref() {
            ExecutorEvent::Subscribed(info) => {
                ex = info.executor_id.as_str().to_owned();
                ag = info.agent_id.as_str().to_owned();
                "SUBSCRIBED"
            }
            ExecutorEvent::Launch(t) => {
                tk = t.task_id.as_str().to_owned();
                rl = t.role.as_str().to_owned();
                "LAUNCH"
            }
            ExecutorEvent::LaunchGroup(g) => {
                rl = g.role.as_str().to_owned();
                "LAUNCH_GROUP"
            }
            ExecutorEvent::Kill(t, _) => {
                tk = t.as_str().to_owned();
                "KILL"
            }
            ExecutorEvent::Acknowledged(t, u) => {
                tk = t.as_str().to_owned();
                uuid = u.as_str().as_bytes().to_vec();
                "ACKNOWLEDGED"
            }
            ExecutorEvent::Message(_) => "MESSAGE",
            ExecutorEvent::Shutdown(_) => "SHUTDOWN",
            ExecutorEvent::Error(_) => "ERROR",
            ExecutorEvent::Heartbeat => "HEARTBEAT",
        },
        WireMessage::OperatorCall(_) => "MASTER_OPERATOR_CALL",
        WireMessage::OperatorResponse(_) => "MASTER_OPERATOR_RESPONSE",
        WireMessage::OperatorEvent(_) => "MASTER_OPERATOR_EVENT",
        WireMessage::ResourceProviderCall(_) => "RESOURCE_PROVIDER_CALL",
        WireMessage::ResourceProviderEvent(_) => "RESOURCE_PROVIDER_EVENT",
        WireMessage::AgentOperatorCall(_) => "AGENT_OPERATOR_CALL",
        WireMessage::AgentOperatorResponse(_) => "AGENT_OPERATOR_RESPONSE",
        WireMessage::RaftRpc(_) => "RAFT_RPC",
    };
    (mtype.to_owned(), fw, ag, tk, ex, rl, offers, uuid)
}

/// Encodes a [`WireEnvelope`] into authentic Protocol Buffers binary wire format (`syntax = "proto3"`):
/// - Field `1` (`wire_type = 0`, tag `0x08`): `uint32 version` (varint)
/// - Field `2` (`wire_type = 0`, tag `0x10`): `uint64 sequence` (varint)
/// - Field `3` (`wire_type = 0`, tag `0x18`): `MessageKind kind` (varint `1..=22`)
/// - Field `4` (`wire_type = 2`, tag `0x22`): `MesosV1ProtobufSubmessage submessage_payload`
///   encoded with `prost::Message::encode_to_vec()` (authentic Protobuf v3 wire tags, NOT `rkyv`)
/// - Field `5` (`wire_type = 5`, tag `0x2D`): `fixed32 payload_crc32` (4-byte little-endian IEEE CRC32)
///
/// # Arguments
///
/// * `envelope` - [`WireEnvelope`] to encode.
///
/// # Returns
///
/// Protobuf wire-encoded `Vec<u8>`.
///
/// # Errors
///
/// Returns [`ArbiterError::JsonCodec`] or [`ArbiterError::ProtobufCodec`] if serialization fails
/// or exceeds [`MAX_WIRE_FRAME_BYTES`].
pub fn encode_protobuf_envelope(envelope: &WireEnvelope) -> ArbiterResult<Vec<u8>> {
    use prost::Message as _;

    let pb_sub = MesosV1ProtobufSubmessage::from_wire_message(&envelope.message)?;
    let submsg = pb_sub.encode_to_vec();
    if submsg.len() > MAX_WIRE_FRAME_BYTES as usize {
        return Err(ProtobufCodecError::new(
            4,
            2,
            "submessage payload exceeds MAX_WIRE_FRAME_BYTES",
        )
        .into());
    }
    let crc = compute_wire_crc32(&submsg);
    let mut out = Vec::with_capacity(24 + submsg.len());
    // Field 1 (tag = (1 << 3) | 0 = 0x08): version
    encode_protobuf_varint(0x08, &mut out);
    encode_protobuf_varint(u64::from(envelope.version), &mut out);
    // Field 2 (tag = (2 << 3) | 0 = 0x10): sequence
    encode_protobuf_varint(0x10, &mut out);
    encode_protobuf_varint(envelope.sequence, &mut out);
    // Field 3 (tag = (3 << 3) | 0 = 0x18): message kind enum
    encode_protobuf_varint(0x18, &mut out);
    encode_protobuf_varint(wire_message_protobuf_tag(&envelope.message), &mut out);
    // Field 4 (tag = (4 << 3) | 2 = 0x22): length-delimited prost MesosV1ProtobufSubmessage bytes
    encode_protobuf_varint(0x22, &mut out);
    encode_protobuf_varint(submsg.len() as u64, &mut out);
    out.extend_from_slice(&submsg);
    // Field 5 (tag = (5 << 3) | 5 = 0x2D): fixed32 IEEE CRC32
    encode_protobuf_varint(0x2D, &mut out);
    out.extend_from_slice(&crc.to_le_bytes());
    Ok(out)
}

/// Decodes and validates a [`WireEnvelope`] from Protocol Buffers binary wire format (`syntax = "proto3"`).
///
/// Decodes field 4 as a genuine `prost`-encoded [`MesosV1ProtobufSubmessage`] (and falls back to
/// `rkyv` only if legacy raw `rkyv` bytes were supplied in field 4).
///
/// # Arguments
///
/// * `bytes` - Raw Protobuf wire bytes.
///
/// # Returns
///
/// Decoded [`WireEnvelope`].
///
/// # Errors
///
/// Returns [`ArbiterError::ProtobufCodec`], [`ArbiterError::DeserializationError`], or [`ArbiterError::JsonCodec`]
/// if the wire tags, varints, CRC32, version, or submessage bytes are invalid.
pub fn decode_protobuf_envelope(bytes: &[u8]) -> ArbiterResult<WireEnvelope> {
    if bytes.is_empty() {
        return Err(ProtobufCodecError::new(0, 0, "empty protobuf payload").into());
    }
    decode_protobuf_raw_wire(bytes)
}

/// Decodes raw Protocol Buffers tag-wire fields into a validated [`WireEnvelope`].
///
/// # Arguments
///
/// * `bytes` - Raw Protobuf message slice.
///
/// # Returns
///
/// Validated [`WireEnvelope`].
///
/// # Errors
///
/// Returns [`ArbiterError::ProtobufCodec`] or [`ArbiterError::DeserializationError`] if malformed.
#[allow(clippy::too_many_lines)]
fn decode_protobuf_raw_wire(bytes: &[u8]) -> ArbiterResult<WireEnvelope> {
    use prost::Message as _;

    let mut cursor = 0_usize;
    let mut version_opt: Option<u16> = None;
    let mut seq_opt: Option<u64> = None;
    let mut kind_opt: Option<u64> = None;
    let mut payload_opt: Option<&[u8]> = None;
    let mut crc_opt: Option<u32> = None;

    while cursor < bytes.len() {
        let tag_key = decode_protobuf_varint(bytes, &mut cursor, 0)?;
        let field_num = u32::try_from(tag_key >> 3).unwrap_or(u32::MAX);
        let wire_type = u8::try_from(tag_key & 0x07).unwrap_or(0xFF);
        if field_num == 0 {
            return Err(ProtobufCodecError::new(
                0,
                wire_type,
                "invalid field number 0 in protobuf",
            )
            .into());
        }
        match (field_num, wire_type) {
            (1, 0) => {
                let v = decode_protobuf_varint(bytes, &mut cursor, 1)?;
                version_opt = Some(u16::try_from(v).unwrap_or(u16::MAX));
            }
            (2, 0) => {
                seq_opt = Some(decode_protobuf_varint(bytes, &mut cursor, 2)?);
            }
            (3, 0) => {
                kind_opt = Some(decode_protobuf_varint(bytes, &mut cursor, 3)?);
            }
            (4, 2) => {
                let len_u64 = decode_protobuf_varint(bytes, &mut cursor, 4)?;
                if len_u64 > u64::from(MAX_WIRE_FRAME_BYTES) {
                    return Err(ProtobufCodecError::new(
                        4,
                        2,
                        "length-delimited field 4 exceeds MAX_WIRE_FRAME_BYTES",
                    )
                    .into());
                }
                let len = usize::try_from(len_u64).unwrap_or(usize::MAX);
                let end = cursor.saturating_add(len);
                let Some(sub) = bytes.get(cursor..end) else {
                    return Err(ProtobufCodecError::new(
                        4,
                        2,
                        "truncated length-delimited submessage",
                    )
                    .into());
                };
                payload_opt = Some(sub);
                cursor = end;
            }
            (5, 5) => {
                let end = cursor.saturating_add(4);
                let Some(crc_slice) = bytes.get(cursor..end) else {
                    return Err(
                        ProtobufCodecError::new(5, 5, "truncated fixed32 CRC32 field").into(),
                    );
                };
                let mut crc_arr = [0_u8; 4];
                crc_arr.copy_from_slice(crc_slice);
                crc_opt = Some(u32::from_le_bytes(crc_arr));
                cursor = end;
            }
            (_, 0) => {
                // Skip unknown varint field for proto3 forward compatibility
                let _ = decode_protobuf_varint(bytes, &mut cursor, field_num)?;
            }
            (_, _) => {
                return Err(ProtobufCodecError::new(
                    field_num,
                    wire_type,
                    "unsupported protobuf wire type",
                )
                .into());
            }
        }
    }

    let Some(version) = version_opt else {
        return Err(ProtobufCodecError::new(1, 0, "missing required version field 1").into());
    };
    if version != WIRE_SCHEMA_VERSION {
        return Err(ArbiterError::DeserializationError {
            format: "application/x-protobuf".to_owned(),
            reason: format!(
                "unsupported protobuf wire schema version {version} (expected {WIRE_SCHEMA_VERSION})"
            ),
        });
    }
    let Some(sequence) = seq_opt else {
        return Err(ProtobufCodecError::new(2, 0, "missing required sequence field 2").into());
    };
    let Some(kind_tag) = kind_opt else {
        return Err(ProtobufCodecError::new(3, 0, "missing required kind field 3").into());
    };
    let Some(payload) = payload_opt else {
        return Err(ProtobufCodecError::new(4, 2, "missing required submessage field 4").into());
    };
    if let Some(expected_crc) = crc_opt {
        let actual_crc = compute_wire_crc32(payload);
        if actual_crc != expected_crc {
            return Err(ProtobufCodecError::new(5, 5, "protobuf submessage CRC32 mismatch").into());
        }
    }
    let pb_sub = MesosV1ProtobufSubmessage::decode(payload).map_err(ProtobufCodecError::from)?;
    let message = pb_sub.into_wire_message()?;
    if wire_message_protobuf_tag(&message) != kind_tag {
        return Err(ProtobufCodecError::new(
            3,
            0,
            "protobuf outer header metadata does not match submessage envelope",
        )
        .into());
    }
    Ok(WireEnvelope {
        version,
        sequence,
        message,
    })
}

/// Encodes a [`WireEnvelope`] as a Mesos v1 binary `RecordIO` Protobuf frame (`<decimal-byte-len>\n<protobuf-bytes>`).
///
/// # Arguments
///
/// * `envelope` - [`WireEnvelope`] to encode.
///
/// # Returns
///
/// Binary `RecordIO` Protobuf frame bytes.
///
/// # Errors
///
/// Returns [`ArbiterError::ProtobufCodec`] or [`ArbiterError::RkyvCodec`] on serialization failure.
pub fn encode_protobuf_recordio_frame(envelope: &WireEnvelope) -> ArbiterResult<Vec<u8>> {
    let pb_bytes = encode_protobuf_envelope(envelope)?;
    let prefix = format!("{}\n", pb_bytes.len());
    let mut out = Vec::with_capacity(prefix.len() + pb_bytes.len());
    out.extend_from_slice(prefix.as_bytes());
    out.extend_from_slice(&pb_bytes);
    Ok(out)
}

/// Decodes one or more concatenated binary `RecordIO` Protobuf frames (`<decimal-byte-len>\n<protobuf-bytes>`)
/// into [`WireEnvelope`]s.
///
/// # Arguments
///
/// * `bytes` - Raw binary `RecordIO` stream slice.
///
/// # Returns
///
/// Vector of decoded [`WireEnvelope`]s.
///
/// # Errors
///
/// Returns [`ArbiterError::ProtobufCodec`] or [`ArbiterError::DeserializationError`] if malformed.
pub fn decode_protobuf_recordio_frames(bytes: &[u8]) -> ArbiterResult<Vec<WireEnvelope>> {
    let mut cursor = bytes;
    let mut frames = Vec::new();
    while !cursor.is_empty() {
        let Some(nl_pos) = cursor.iter().position(|&b| b == b'\n') else {
            return Err(ProtobufCodecError::new(
                0,
                2,
                "missing newline after binary RecordIO byte length",
            )
            .into());
        };
        let len_str = core::str::from_utf8(cursor.get(..nl_pos).unwrap_or(&[])).map_err(|_| {
            ProtobufCodecError::new(0, 2, "non-ASCII byte length in binary RecordIO")
        })?;
        let byte_len = len_str.trim().parse::<usize>().map_err(|_| {
            ProtobufCodecError::new(0, 2, "invalid decimal byte length in binary RecordIO")
        })?;
        let body_start = nl_pos.saturating_add(1);
        let body_end = body_start.saturating_add(byte_len);
        let Some(pb_slice) = cursor.get(body_start..body_end) else {
            return Err(ProtobufCodecError::new(
                0,
                2,
                "truncated binary RecordIO protobuf payload",
            )
            .into());
        };
        let env = decode_protobuf_envelope(pb_slice)?;
        frames.push(env);
        cursor = cursor.get(body_end..).unwrap_or(&[]);
    }
    Ok(frames)
}

/// Content-Type negotiation mode for HTTP/QUIC wire payloads.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WireCodecContentType {
    /// `application/json` (standard Mesos v1 JSON DTO encoding).
    #[default]
    ApplicationJson,
    /// `application/x-protobuf` (Mesos v1 binary Protobuf & `RecordIO` wire encoding).
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

    /// Encodes `envelope` according to this [`WireCodecContentType`]:
    /// - `ApplicationJson`: UTF-8 JSON bytes
    /// - `ApplicationProtobuf`: Mesos v1 binary Protocol Buffers wire encoding
    /// - `ApplicationRkyv`: 16-byte `ARBW` header + zero-copy `rkyv` binary payload
    ///
    /// # Arguments
    ///
    /// * `envelope` - [`WireEnvelope`] to encode.
    ///
    /// # Returns
    ///
    /// Encoded wire payload bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::JsonCodec`], [`ArbiterError::ProtobufCodec`], [`ArbiterError::RkyvCodec`], or [`ArbiterError::SerializationError`].
    pub fn encode_envelope(self, envelope: &WireEnvelope) -> ArbiterResult<Vec<u8>> {
        match self {
            Self::ApplicationJson => envelope.to_json_string().map(String::into_bytes),
            Self::ApplicationProtobuf => encode_protobuf_envelope(envelope),
            Self::ApplicationRkyv => {
                let rkyv_bytes = envelope.to_rkyv_bytes()?;
                let payload_len = u32::try_from(rkyv_bytes.len()).unwrap_or(u32::MAX);
                let header = WireFrameHeader::new(0, 0, payload_len)?;
                let mut framed = Vec::with_capacity(WIRE_FRAME_HEADER_LEN + rkyv_bytes.len());
                framed.extend_from_slice(&header.to_bytes());
                framed.extend_from_slice(&rkyv_bytes);
                Ok(framed)
            }
        }
    }

    /// Decodes a [`WireEnvelope`] from `bytes` according to this [`WireCodecContentType`].
    ///
    /// # Arguments
    ///
    /// * `bytes` - Raw request/response payload bytes.
    ///
    /// # Returns
    ///
    /// Decoded [`WireEnvelope`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::DeserializationError`], [`ArbiterError::ProtobufCodec`], [`ArbiterError::JsonCodec`], or [`ArbiterError::RkyvCodec`].
    pub fn decode_envelope(self, bytes: &[u8]) -> ArbiterResult<WireEnvelope> {
        match self {
            Self::ApplicationJson => {
                let text = core::str::from_utf8(bytes).map_err(|_| {
                    ArbiterError::DeserializationError {
                        format: "application/json".to_owned(),
                        reason: "payload is not valid UTF-8".to_owned(),
                    }
                })?;
                WireEnvelope::from_json_str(text)
            }
            Self::ApplicationProtobuf => decode_protobuf_envelope(bytes),
            Self::ApplicationRkyv => {
                if bytes.get(..4) == Some(&WIRE_FRAME_MAGIC) {
                    let header = WireFrameHeader::from_bytes(bytes)?;
                    let end_idx = WIRE_FRAME_HEADER_LEN + header.payload_len as usize;
                    let Some(payload) = bytes.get(WIRE_FRAME_HEADER_LEN..end_idx) else {
                        return Err(ArbiterError::DeserializationError {
                            format: "ARBW".to_owned(),
                            reason: "truncated ARBW payload".to_owned(),
                        });
                    };
                    WireEnvelope::from_rkyv_bytes(payload)
                } else {
                    WireEnvelope::from_rkyv_bytes(bytes)
                }
            }
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
            SchedulerCall::RespondInverseOffer(
                FrameworkId::default(),
                Vec::new(),
                InverseOfferResponse::AcceptMaintenance
            )
        );
        let log_call =
            OperatorCall::set_logging_level_typed(LoggingLevel::Debug, BenchmarkTicks::new(5));
        assert_eq!(
            log_call,
            OperatorCall::SetLoggingLevel(LoggingLevel::Debug, BenchmarkTicks::new(5))
        );
        let sp = SandboxPath::new("sandbox/stdout").unwrap_or_default();
        let read_call = OperatorCall::read_file_typed(
            sp.clone(),
            FileReadOffset::new(10),
            FileReadLength::new(100),
        );
        assert_eq!(
            read_call,
            OperatorCall::ReadFile(sp, FileReadOffset::new(10), FileReadLength::new(100))
        );
        let log_resp = OperatorResponse::logging_level_typed(LoggingLevel::Info);
        assert_eq!(log_resp, OperatorResponse::LoggingLevel(LoggingLevel::Info));
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
        let bin = env.to_rkyv_bytes().unwrap_or_default();
        let aligned = env.to_aligned_bytes().unwrap_or_default();
        let archived = WireEnvelope::access_archived(&aligned);
        assert!(archived.is_ok());
        assert_eq!(archived.map(|a| a.sequence.to_native()), Ok(env.sequence));
        assert_eq!(
            WireEnvelope::view_archived(&aligned).map(|a| a.sequence.to_native()),
            Ok(env.sequence)
        );
        assert_eq!(WireEnvelope::from_rkyv_bytes(&bin), Ok(env.clone()));

        // Corrupted binary payload rejected with ArbiterError::RkyvCodec
        assert!(WireEnvelope::from_rkyv_bytes(b"corrupted").is_err());
        assert!(WireEnvelope::access_archived(b"corrupted").is_err());
        assert!(WireEnvelope::view_archived(b"corrupted").is_err());

        // Unsupported version in rkyv rejected
        let mut bad_ver = env.clone();
        bad_ver.version = 99;
        let bad_bin = bad_ver.to_rkyv_bytes().unwrap_or_default();
        let bad_aligned = bad_ver.to_aligned_bytes().unwrap_or_default();
        assert!(WireEnvelope::from_rkyv_bytes(&bad_bin).is_err());
        assert!(WireEnvelope::access_archived(&bad_aligned).is_err());
        assert!(WireEnvelope::view_archived(&bad_aligned).is_err());

        // JSON roundtrip
        let json = env.to_json_string().unwrap_or_default();
        assert_eq!(WireEnvelope::from_json_str(&json), Ok(env));

        // Malformed JSON rejected
        assert!(WireEnvelope::from_json_str("{bad").is_err());

        // Unsupported version in JSON rejected
        let bad_json = bad_ver.to_json_string().unwrap_or_default();
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
    fn test_recordio_stream_encoder_and_http_chunked() {
        let env = WireEnvelope::new(
            100,
            WireMessage::AgentHeartbeat(AgentHeartbeat {
                agent_id: AgentId::new("agent-1").unwrap_or_default(),
                tick: 42,
                healthy_tasks: Vec::new(),
            }),
        );
        // RecordIoStreamEncoder & HTTP chunked RecordIO roundtrip + error branches
        let mut stream_encoder = RecordIoStreamEncoder::new();
        assert_eq!(stream_encoder.frames_encoded(), 0);
        assert_eq!(stream_encoder.buffered_bytes(), 0);
        let pushed_plain = stream_encoder.push_frame(&env);
        assert!(pushed_plain.is_ok());
        assert_eq!(stream_encoder.frames_encoded(), 1);
        assert!(stream_encoder.buffered_bytes() > 0);
        let plain_stream = stream_encoder.take_buffer();
        assert_eq!(stream_encoder.buffered_bytes(), 0);
        assert_eq!(decode_recordio_frames(&plain_stream), Ok(vec![env.clone()]));

        let mut chunk_enc = RecordIoStreamEncoder::new();
        assert!(chunk_enc.push_http_chunked_frame(&env).is_ok());
        assert_eq!(chunk_enc.finish_http_chunked_stream(), "0\r\n\r\n");
        let chunked_stream = chunk_enc.take_buffer();
        assert_eq!(
            decode_http_chunked_recordio_frames(&chunked_stream),
            Ok(vec![env])
        );
        assert_eq!(decode_http_chunked_recordio_frames(""), Ok(Vec::new()));
        assert!(decode_http_chunked_recordio_frames("no-crlf").is_err());
        assert!(decode_http_chunked_recordio_frames("zz\r\n{}\r\n").is_err());
        assert!(decode_http_chunked_recordio_frames("ff\r\nshort").is_err());
        assert!(decode_http_chunked_recordio_frames("2\r\nabXX").is_err());

        // Oversized payload > MAX_WIRE_FRAME_BYTES rejected by push_frame and push_http_chunked_frame
        let huge_str = "x".repeat(MAX_WIRE_FRAME_BYTES as usize + 64);
        let huge_env = WireEnvelope::new(
            1,
            WireMessage::SchedulerEvent(Box::new(SchedulerEvent::Error(huge_str))),
        );
        assert!(stream_encoder.push_frame(&huge_env).is_err());
        assert!(stream_encoder.push_http_chunked_frame(&huge_env).is_err());
    }

    #[test]
    #[allow(clippy::too_many_lines, clippy::cognitive_complexity)]
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
            WireMessage::ExecutorCall(Box::new(ExecutorCall::Heartbeat(
                ExecutorId::new("a").unwrap_or_default(),
            ))),
            WireMessage::ExecutorEvent(Box::new(ExecutorEvent::Subscribed(ExecutorInfo {
                executor_id: ExecutorId::new("a").unwrap_or_default(),
                agent_id: AgentId::new("a").unwrap_or_default(),
            }))),
            WireMessage::ExecutorEvent(Box::new(ExecutorEvent::Heartbeat)),
            WireMessage::OperatorCall(Box::new(OperatorCall::UpdateWeights(Vec::new()))),
            WireMessage::OperatorCall(Box::new(OperatorCall::GetOperations)),
            WireMessage::OperatorCall(Box::new(OperatorCall::UpdateQuota(
                RoleName::new("a").unwrap_or_default(),
                Quota {
                    id: arbiter_core::ids::QuotaId::new("q").unwrap_or_default(),
                    guaranteed_min: ResourceBundle::zero(),
                    hard_max: ResourceBundle::zero(),
                    allow_burst_borrowing: false,
                    weight: WeightBasisPoints::STANDARD,
                },
            ))),
            WireMessage::OperatorCall(Box::new(OperatorCall::TeardownFramework(
                FrameworkId::new("a").unwrap_or_default(),
            ))),
            WireMessage::OperatorResponse(Box::new(OperatorResponse::Health(true))),
            WireMessage::OperatorResponse(Box::new(OperatorResponse::Operations(Vec::new()))),
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
            let tag = wire_message_protobuf_tag(&msg);
            assert!((1..=22).contains(&tag));
            let e = WireEnvelope::new(1, msg);
            let bytes = e.to_rkyv_bytes().unwrap_or_default();
            let summary = WireEnvelope::inspect_framed_header_zero_copy(&bytes);
            assert!(summary.is_ok());
            assert_eq!(WireEnvelope::from_rkyv_bytes(&bytes), Ok(e.clone()));
            let pb_bytes = encode_protobuf_envelope(&e).unwrap_or_default();
            assert_eq!(decode_protobuf_envelope(&pb_bytes), Ok(e));
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
            let check_env = WireEnvelope::new(
                7,
                WireMessage::OperatorCall(Box::new(OperatorCall::GetHealth)),
            );
            let encoded = ct.encode_envelope(&check_env).unwrap_or_default();
            assert_eq!(ct.decode_envelope(&encoded), Ok(check_env));
        }
        assert!(
            WireCodecContentType::ApplicationJson
                .decode_envelope(&[0xFF, 0xFE])
                .is_err()
        );
        assert!(
            WireCodecContentType::ApplicationProtobuf
                .decode_envelope(&[0xFF, 0xFE])
                .is_err()
        );
        assert!(
            WireCodecContentType::ApplicationProtobuf
                .decode_envelope(b"")
                .is_err()
        );
        let check_env = WireEnvelope::new(
            8,
            WireMessage::OperatorCall(Box::new(OperatorCall::GetHealth)),
        );
        let raw_rkyv = check_env.to_rkyv_bytes().unwrap_or_default();
        assert_eq!(
            WireCodecContentType::ApplicationRkyv.decode_envelope(&raw_rkyv),
            Ok(check_env.clone())
        );
        let mut truncated_arbw = WireFrameHeader::new(0, 0, 100)
            .unwrap_or_default()
            .to_bytes()
            .to_vec();
        truncated_arbw.extend_from_slice(b"short");
        assert!(
            WireCodecContentType::ApplicationRkyv
                .decode_envelope(&truncated_arbw)
                .is_err()
        );

        // Protobuf varint, binary RecordIO, and error branches
        let pb_rec1 = encode_protobuf_recordio_frame(&check_env).unwrap_or_default();
        assert_eq!(
            decode_protobuf_recordio_frames(&pb_rec1),
            Ok(vec![check_env.clone()])
        );
        assert!(decode_protobuf_recordio_frames(b"no-newline").is_err());
        assert!(decode_protobuf_recordio_frames(b"\xFF\xFE\n{}").is_err());
        assert!(decode_protobuf_recordio_frames(b"abc\n{}").is_err());
        assert!(decode_protobuf_recordio_frames(b"999\nshort").is_err());

        // Oversized submessage in encode_protobuf_envelope
        let huge_str = "x".repeat(MAX_WIRE_FRAME_BYTES as usize + 64);
        let huge_env = WireEnvelope::new(
            1,
            WireMessage::SchedulerEvent(Box::new(SchedulerEvent::Error(huge_str))),
        );
        assert!(encode_protobuf_envelope(&huge_env).is_err());

        // Varint overflow (> 64 bits) and truncated varint
        let mut cur = 0_usize;
        assert!(decode_protobuf_varint(&[0x80; 11], &mut cur, 1).is_err());
        let mut cur2 = 0_usize;
        assert!(decode_protobuf_varint(&[0x80], &mut cur2, 1).is_err());

        // Field 0 rejected
        assert!(decode_protobuf_envelope(&[0x00, 0x01]).is_err());
        // Unsupported wire type (wire_type = 1, 64-bit) rejected
        assert!(decode_protobuf_envelope(&[0x09, 0x01]).is_err());
        // Unknown varint field (field 99, wire_type 0) skipped cleanly, then missing required fields checked
        let mut with_unknown = Vec::new();
        encode_protobuf_varint(99 << 3, &mut with_unknown);
        encode_protobuf_varint(42, &mut with_unknown);
        assert!(decode_protobuf_envelope(&with_unknown).is_err()); // missing field 1

        // Missing field 2, 3, 4, version mismatch, oversized field 4, truncated field 4, truncated field 5, CRC mismatch, metadata mismatch
        let mut f1_only = Vec::new();
        encode_protobuf_varint(0x08, &mut f1_only);
        encode_protobuf_varint(u64::from(WIRE_SCHEMA_VERSION), &mut f1_only);
        assert!(decode_protobuf_envelope(&f1_only).is_err()); // missing field 2

        let mut bad_ver_pb = Vec::new();
        encode_protobuf_varint(0x08, &mut bad_ver_pb);
        encode_protobuf_varint(99, &mut bad_ver_pb);
        assert!(decode_protobuf_envelope(&bad_ver_pb).is_err()); // unsupported version

        let mut f1_f2 = f1_only;
        encode_protobuf_varint(0x10, &mut f1_f2);
        encode_protobuf_varint(8, &mut f1_f2);
        assert!(decode_protobuf_envelope(&f1_f2).is_err()); // missing field 3

        let mut f1_f2_f3 = f1_f2;
        encode_protobuf_varint(0x18, &mut f1_f2_f3);
        encode_protobuf_varint(15, &mut f1_f2_f3);
        assert!(decode_protobuf_envelope(&f1_f2_f3).is_err()); // missing field 4

        let mut huge_f4 = f1_f2_f3.clone();
        encode_protobuf_varint(0x22, &mut huge_f4);
        encode_protobuf_varint(u64::from(MAX_WIRE_FRAME_BYTES) + 100, &mut huge_f4);
        assert!(decode_protobuf_envelope(&huge_f4).is_err());

        let mut trunc_f4 = f1_f2_f3.clone();
        encode_protobuf_varint(0x22, &mut trunc_f4);
        encode_protobuf_varint(50, &mut trunc_f4);
        trunc_f4.extend_from_slice(b"short");
        assert!(decode_protobuf_envelope(&trunc_f4).is_err());

        let mut trunc_f5 = f1_f2_f3.clone();
        encode_protobuf_varint(0x2D, &mut trunc_f5);
        trunc_f5.extend_from_slice(&[1, 2]);
        assert!(decode_protobuf_envelope(&trunc_f5).is_err());

        let mut bad_crc_pb = encode_protobuf_envelope(&check_env).unwrap_or_default();
        for last in bad_crc_pb.iter_mut().rev().take(1) {
            *last ^= 0xFF;
        }
        assert!(decode_protobuf_envelope(&bad_crc_pb).is_err());

        // Valid without field 5 CRC (using prost MesosV1ProtobufSubmessage)
        let pb_sub_bytes = {
            use prost::Message as _;
            MesosV1ProtobufSubmessage::from_wire_message(&check_env.message)
                .unwrap_or_default()
                .encode_to_vec()
        };
        let mut no_crc_valid = f1_f2_f3.clone();
        encode_protobuf_varint(0x22, &mut no_crc_valid);
        encode_protobuf_varint(pb_sub_bytes.len() as u64, &mut no_crc_valid);
        no_crc_valid.extend_from_slice(&pb_sub_bytes);
        assert_eq!(decode_protobuf_envelope(&no_crc_valid), Ok(check_env));

        // Metadata mismatch on kind tag (field 3 = 99 instead of 15)
        let mut no_crc_mismatch = f1_f2_f3.clone();
        encode_protobuf_varint(0x18, &mut no_crc_mismatch);
        encode_protobuf_varint(99, &mut no_crc_mismatch);
        encode_protobuf_varint(0x22, &mut no_crc_mismatch);
        encode_protobuf_varint(pb_sub_bytes.len() as u64, &mut no_crc_mismatch);
        no_crc_mismatch.extend_from_slice(&pb_sub_bytes);
        assert!(decode_protobuf_envelope(&no_crc_mismatch).is_err());

        // Empty mesos_type in MesosV1ProtobufSubmessage rejected
        let empty_sub = MesosV1ProtobufSubmessage::default();
        assert!(empty_sub.into_wire_message().is_err());

        // Invalid prost submessage bytes in field 4 rejected
        let mut bad_prost_f4 = f1_f2_f3;
        let bad_sub_bytes = [0x80_u8; 12];
        encode_protobuf_varint(0x22, &mut bad_prost_f4);
        encode_protobuf_varint(bad_sub_bytes.len() as u64, &mut bad_prost_f4);
        bad_prost_f4.extend_from_slice(&bad_sub_bytes);
        assert!(decode_protobuf_envelope(&bad_prost_f4).is_err());
    }

    #[test]
    #[allow(clippy::too_many_lines, clippy::similar_names, clippy::redundant_clone)]
    fn test_mesos_v1_protobuf_submessage_all_variants() {
        let fw = FrameworkId::new("fw-pb").unwrap_or_default();
        let ag = AgentId::new("ag-pb").unwrap_or_default();
        let tk = TaskId::new("tk-pb").unwrap_or_default();
        let ex = ExecutorId::new("ex-pb").unwrap_or_default();
        let rl = RoleName::new("rl-pb").unwrap_or_default();
        let oid = OfferId::new("off-pb").unwrap_or_default();
        let opid = OperationId::new("op-pb").unwrap_or_default();
        let uuid = StatusUpdateUuid::new("uuid-pb").unwrap_or_default();
        let task_spec = TaskSpec {
            task_id: tk.clone(),
            role: rl.clone(),
            framework_id: Some(fw.clone()),
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
                command: "/bin/true".to_owned(),
                args: Vec::new(),
                env: Vec::new(),
                run_as_user: None,
            },
            artifacts: Vec::new(),
            secrets: Vec::new(),
            health_check: None,
        };
        let gang_spec = TaskGroupSpec {
            group_id: arbiter_core::ids::TaskGroupId::new("gang-pb").unwrap_or_default(),
            role: rl.clone(),
            tasks: vec![task_spec.clone()],
            tpu_slice: None,
            placement_timeout_ms: 1000,
        };
        let offer = ResourceOffer {
            offer_id: oid.clone(),
            framework_id: fw.clone(),
            agent_id: ag.clone(),
            role: rl.clone(),
            resources: ResourceBundle::zero(),
            revocable: false,
            expires_at_tick: 10,
        };
        let inv_offer = InverseOffer {
            inverse_offer_id: oid.clone(),
            framework_id: fw.clone(),
            agent_id: ag.clone(),
            maintenance_window_id: arbiter_core::ids::MaintenanceWindowId::new("mw-pb")
                .unwrap_or_default(),
            resources: ResourceBundle::zero(),
            unavailability_start_tick: BenchmarkTicks::new(10),
        };
        let upd = TaskStatusUpdate {
            task_id: tk.clone(),
            agent_id: ag.clone(),
            state: TaskState::Running,
            message: "ok".to_owned(),
        };

        let variants = vec![
            WireMessage::SubmitDirectJob(SubmitDirectJob::GangJob(gang_spec.clone())),
            WireMessage::ResourceOfferBatch(ResourceOfferBatch {
                framework_id: fw.clone(),
                offers: vec![offer.clone()],
            }),
            WireMessage::AcceptOffers(AcceptOffers {
                framework_id: fw.clone(),
                offer_ids: vec![oid.clone()],
                operations: Vec::new(),
            }),
            WireMessage::SchedulerCall(Box::new(SchedulerCall::Teardown(fw.clone()))),
            WireMessage::SchedulerCall(Box::new(SchedulerCall::Accept(
                AcceptOffers {
                    framework_id: fw.clone(),
                    offer_ids: vec![oid.clone()],
                    operations: Vec::new(),
                },
                Some(opid.clone()),
                OfferFilter::default(),
            ))),
            WireMessage::SchedulerCall(Box::new(SchedulerCall::Decline(
                fw.clone(),
                vec![oid.clone()],
                OfferFilter::default(),
            ))),
            WireMessage::SchedulerCall(Box::new(SchedulerCall::RespondInverseOffer(
                fw.clone(),
                vec![oid.clone()],
                InverseOfferResponse::AcceptMaintenance,
            ))),
            WireMessage::SchedulerCall(Box::new(SchedulerCall::Revive(
                fw.clone(),
                vec![rl.clone()],
            ))),
            WireMessage::SchedulerCall(Box::new(SchedulerCall::Revive(fw.clone(), Vec::new()))),
            WireMessage::SchedulerCall(Box::new(SchedulerCall::Suppress(
                fw.clone(),
                vec![rl.clone()],
            ))),
            WireMessage::SchedulerCall(Box::new(SchedulerCall::Suppress(fw.clone(), Vec::new()))),
            WireMessage::SchedulerCall(Box::new(SchedulerCall::Kill(
                fw.clone(),
                tk.clone(),
                Some(ag.clone()),
                None,
            ))),
            WireMessage::SchedulerCall(Box::new(SchedulerCall::Kill(
                fw.clone(),
                tk.clone(),
                None,
                None,
            ))),
            WireMessage::SchedulerCall(Box::new(SchedulerCall::Shutdown(
                fw.clone(),
                ex.clone(),
                ag.clone(),
            ))),
            WireMessage::SchedulerCall(Box::new(SchedulerCall::Acknowledge(
                fw.clone(),
                ag.clone(),
                tk.clone(),
                uuid.clone(),
            ))),
            WireMessage::SchedulerCall(Box::new(SchedulerCall::AcknowledgeOperationStatus(
                fw.clone(),
                Some(ag.clone()),
                opid.clone(),
                uuid.clone(),
            ))),
            WireMessage::SchedulerCall(Box::new(SchedulerCall::AcknowledgeOperationStatus(
                fw.clone(),
                None,
                opid.clone(),
                uuid.clone(),
            ))),
            WireMessage::SchedulerCall(Box::new(SchedulerCall::ReconcileTasks(
                fw.clone(),
                Vec::new(),
            ))),
            WireMessage::SchedulerCall(Box::new(SchedulerCall::ReconcileOperations(
                fw.clone(),
                Vec::new(),
            ))),
            WireMessage::SchedulerCall(Box::new(SchedulerCall::Message(
                fw.clone(),
                ag.clone(),
                ex.clone(),
                vec![1, 2],
            ))),
            WireMessage::SchedulerCall(Box::new(SchedulerCall::Request(fw.clone(), Vec::new()))),
            WireMessage::SchedulerEvent(Box::new(SchedulerEvent::Offers(vec![offer]))),
            WireMessage::SchedulerEvent(Box::new(SchedulerEvent::InverseOffers(vec![inv_offer]))),
            WireMessage::SchedulerEvent(Box::new(SchedulerEvent::Rescind(
                oid.clone(),
                OfferRescindReason::OfferTtlExpired,
            ))),
            WireMessage::SchedulerEvent(Box::new(SchedulerEvent::RescindInverseOffer(oid))),
            WireMessage::SchedulerEvent(Box::new(SchedulerEvent::Update(
                upd.clone(),
                Some(uuid.clone()),
            ))),
            WireMessage::SchedulerEvent(Box::new(SchedulerEvent::Update(upd.clone(), None))),
            WireMessage::SchedulerEvent(Box::new(SchedulerEvent::OperationUpdate(
                opid.clone(),
                OperationState::Finished,
                "done".to_owned(),
                Some(uuid.clone()),
            ))),
            WireMessage::SchedulerEvent(Box::new(SchedulerEvent::OperationUpdate(
                opid,
                OperationState::Finished,
                "done".to_owned(),
                None,
            ))),
            WireMessage::SchedulerEvent(Box::new(SchedulerEvent::Message(
                ag.clone(),
                fw.clone(),
                ex.clone(),
                vec![3],
            ))),
            WireMessage::SchedulerEvent(Box::new(SchedulerEvent::FailureAgentLost(
                ag.clone(),
                AgentLossReason::HeartbeatTimeout,
            ))),
            WireMessage::SchedulerEvent(Box::new(SchedulerEvent::FailureExecutorLost(
                ag.clone(),
                ex.clone(),
                1,
            ))),
            WireMessage::SchedulerEvent(Box::new(SchedulerEvent::Error("err".to_owned()))),
            WireMessage::SchedulerEvent(Box::new(SchedulerEvent::Heartbeat)),
            WireMessage::ExecutorCall(Box::new(ExecutorCall::Update(
                ex.clone(),
                upd,
                uuid.clone(),
            ))),
            WireMessage::ExecutorCall(Box::new(ExecutorCall::Message(fw, ex, vec![4]))),
            WireMessage::ExecutorEvent(Box::new(ExecutorEvent::Launch(Box::new(task_spec)))),
            WireMessage::ExecutorEvent(Box::new(ExecutorEvent::LaunchGroup(gang_spec))),
            WireMessage::ExecutorEvent(Box::new(ExecutorEvent::Kill(tk.clone(), None))),
            WireMessage::ExecutorEvent(Box::new(ExecutorEvent::Acknowledged(tk, uuid))),
            WireMessage::ExecutorEvent(Box::new(ExecutorEvent::Message(vec![5]))),
            WireMessage::ExecutorEvent(Box::new(ExecutorEvent::Shutdown(BenchmarkTicks::new(5)))),
            WireMessage::ExecutorEvent(Box::new(ExecutorEvent::Error("err".to_owned()))),
        ];

        for (idx, msg) in variants.into_iter().enumerate() {
            let env = WireEnvelope::new(idx as u64 + 1, msg);
            let pb = encode_protobuf_envelope(&env).unwrap_or_default();
            assert_eq!(decode_protobuf_envelope(&pb), Ok(env));
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
            let bin = env.to_rkyv_bytes().unwrap_or_default();
            prop_assert_eq!(WireEnvelope::from_rkyv_bytes(&bin), Ok(env.clone()));

            let json = env.to_json_string().unwrap_or_default();
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
