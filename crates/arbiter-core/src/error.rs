//! Unified error model (`ArbiterError`) and result type alias (`ArbiterResult`) for the Arbiter ecosystem.
//!
//! All failure modes across domain validation, arithmetic, resource accounting, scheduling,
//! consensus, fencing, networking, security, OS isolation, hardware probing, and CLI lifecycle
//! are represented in a single strongly-typed enum using `derive_more`.

use derive_more::{Display, Error, From};
use serde::{Deserialize, Serialize};

/// Standard result alias used uniformly across all Arbiter crates.
pub type ArbiterResult<T> = core::result::Result<T, ArbiterError>;

/// Wrapper error for JSON serialization/deserialization failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display("JSON codec error: {message}")]
pub struct JsonCodecError {
    /// Human-readable description of the codec failure.
    pub message: String,
}

impl From<serde_json::Error> for JsonCodecError {
    /// Converts a `serde_json::Error` into a [`JsonCodecError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `serde_json` error.
    ///
    /// # Returns
    ///
    /// A structured [`JsonCodecError`].
    fn from(err: serde_json::Error) -> Self {
        Self {
            message: err.to_string(),
        }
    }
}

/// Wrapper error for standard library I/O failures (`std::io::Error`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display("I/O operation error ({kind}): {message}")]
pub struct IoOperationError {
    /// Canonical `std::io::ErrorKind` name.
    pub kind: String,
    /// Human-readable description of the I/O failure.
    pub message: String,
}

impl From<std::io::Error> for IoOperationError {
    /// Converts a `std::io::Error` into an [`IoOperationError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `std::io::Error`.
    ///
    /// # Returns
    ///
    /// A structured [`IoOperationError`].
    fn from(err: std::io::Error) -> Self {
        Self {
            kind: format!("{:?}", err.kind()),
            message: err.to_string(),
        }
    }
}

/// Wrapper error for zero-copy `rkyv` binary serialization/deserialization failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display("rkyv binary codec error: {message}")]
pub struct RkyvCodecError {
    /// Human-readable description of the `rkyv` codec failure.
    pub message: String,
}

impl From<rkyv::rancor::Error> for RkyvCodecError {
    /// Converts an `rkyv::rancor::Error` into an [`RkyvCodecError`].
    ///
    /// # Arguments
    ///
    /// * `err` - The underlying `rkyv::rancor::Error`.
    ///
    /// # Returns
    ///
    /// A structured [`RkyvCodecError`].
    fn from(err: rkyv::rancor::Error) -> Self {
        Self {
            message: err.to_string(),
        }
    }
}

/// Wrapper error for QUIC transport and stream framing failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display("QUIC transport error (stream {stream_id}): {message}")]
pub struct QuicTransportError {
    /// Multiplexed QUIC stream identifier (`0` = Control, `1` = Telemetry, `2` = `ArtifactP2p`).
    pub stream_id: u64,
    /// Human-readable description of the QUIC failure.
    pub message: String,
}

impl QuicTransportError {
    /// Creates a new [`QuicTransportError`] for `stream_id` and `message`.
    ///
    /// # Arguments
    ///
    /// * `stream_id` - QUIC stream identifier.
    /// * `message` - Diagnostic failure message.
    ///
    /// # Returns
    ///
    /// Structured [`QuicTransportError`].
    pub fn new(stream_id: u64, message: &str) -> Self {
        Self {
            stream_id,
            message: message.to_owned(),
        }
    }
}

/// Wrapper error for TLS 1.3 handshake and X.509v3 certificate codec failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display("TLS codec error: {message}")]
pub struct RustlsCodecError {
    /// Human-readable description of the TLS failure.
    pub message: String,
}

impl RustlsCodecError {
    /// Creates a new [`RustlsCodecError`].
    ///
    /// # Arguments
    ///
    /// * `message` - Diagnostic TLS error message.
    ///
    /// # Returns
    ///
    /// Structured [`RustlsCodecError`].
    pub fn new(message: &str) -> Self {
        Self {
            message: message.to_owned(),
        }
    }
}

/// Wrapper error for HTTP/1.1, HTTP/2, and `RecordIO` transport failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display("HTTP transport error (status {status_code}): {message}")]
pub struct HttpTransportError {
    /// Associated HTTP status code (`400`, `500`, `502`, etc.).
    pub status_code: u16,
    /// Human-readable description of the HTTP transport failure.
    pub message: String,
}

impl HttpTransportError {
    /// Creates a new [`HttpTransportError`].
    ///
    /// # Arguments
    ///
    /// * `status_code` - HTTP status code.
    /// * `message` - Diagnostic HTTP error message.
    ///
    /// # Returns
    ///
    /// Structured [`HttpTransportError`].
    pub fn new(status_code: u16, message: &str) -> Self {
        Self {
            status_code,
            message: message.to_owned(),
        }
    }
}

/// Wrapper error for RFC 6455 WebSocket upgrade and frame codec failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display("WebSocket codec error: {message}")]
pub struct WebSocketCodecError {
    /// Human-readable description of the WebSocket failure.
    pub message: String,
}

impl WebSocketCodecError {
    /// Creates a new [`WebSocketCodecError`].
    ///
    /// # Arguments
    ///
    /// * `message` - Diagnostic WebSocket error message.
    ///
    /// # Returns
    ///
    /// Structured [`WebSocketCodecError`].
    pub fn new(message: &str) -> Self {
        Self {
            message: message.to_owned(),
        }
    }
}

/// Wrapper error for external etcd v3 gRPC/HTTP2 client failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display("etcd v3 client error on '{endpoint}': {message}")]
pub struct EtcdClientError {
    /// Target etcd v3 endpoint URI.
    pub endpoint: String,
    /// Human-readable description of the etcd client failure.
    pub message: String,
}

impl EtcdClientError {
    /// Creates a new [`EtcdClientError`].
    ///
    /// # Arguments
    ///
    /// * `endpoint` - etcd endpoint URI.
    /// * `message` - Diagnostic failure message.
    ///
    /// # Returns
    ///
    /// Structured [`EtcdClientError`].
    pub fn new(endpoint: &str, message: &str) -> Self {
        Self {
            endpoint: endpoint.to_owned(),
            message: message.to_owned(),
        }
    }
}

/// Wrapper error for external `PostgreSQL` wire-protocol SQL client failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display("PostgreSQL client error (SQLSTATE {sqlstate}): {message}")]
pub struct PostgresClientError {
    /// 5-character SQLSTATE code (e.g., `"40001"` serialization failure, `"08006"` connection failure).
    pub sqlstate: String,
    /// Human-readable description of the `PostgreSQL` client failure.
    pub message: String,
}

impl PostgresClientError {
    /// Creates a new [`PostgresClientError`].
    ///
    /// # Arguments
    ///
    /// * `sqlstate` - 5-character SQLSTATE code.
    /// * `message` - Diagnostic failure message.
    ///
    /// # Returns
    ///
    /// Structured [`PostgresClientError`].
    pub fn new(sqlstate: &str, message: &str) -> Self {
        Self {
            sqlstate: sqlstate.to_owned(),
            message: message.to_owned(),
        }
    }
}

/// Wrapper error for Tier-2 Out-of-Band Redfish BMC HTTPS power fencing failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display("Redfish BMC fence error on '{bmc_endpoint}' (HTTP {status_code}): {message}")]
pub struct RedfishFenceError {
    /// Target BMC Redfish endpoint URI.
    pub bmc_endpoint: String,
    /// HTTP status code returned by the BMC (`400`, `401`, `500`, `503`, etc.).
    pub status_code: u16,
    /// Human-readable diagnostic message from the Redfish response.
    pub message: String,
}

impl RedfishFenceError {
    /// Creates a new [`RedfishFenceError`].
    ///
    /// # Arguments
    ///
    /// * `bmc_endpoint` - Target BMC Redfish URI.
    /// * `status_code` - HTTP status code.
    /// * `message` - Diagnostic failure message.
    ///
    /// # Returns
    ///
    /// Structured [`RedfishFenceError`].
    pub fn new(bmc_endpoint: &str, status_code: u16, message: &str) -> Self {
        Self {
            bmc_endpoint: bmc_endpoint.to_owned(),
            status_code,
            message: message.to_owned(),
        }
    }
}

/// Wrapper error for Tier-2 Out-of-Band IPMI v2 RMCP+ chassis power control failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display("IPMI v2 fence error on '{bmc_address}' (code 0x{completion_code:02x}): {reason}")]
pub struct IpmiFenceError {
    /// Target BMC address (`host:623`).
    pub bmc_address: String,
    /// IPMI completion code byte (`0x00` = normal, `0xC0` = node busy, etc.).
    pub completion_code: u8,
    /// Human-readable description of the IPMI failure.
    pub reason: String,
}

impl IpmiFenceError {
    /// Creates a new [`IpmiFenceError`].
    ///
    /// # Arguments
    ///
    /// * `bmc_address` - Target BMC IP/host address.
    /// * `completion_code` - Raw IPMI completion code byte.
    /// * `reason` - Diagnostic failure reason.
    ///
    /// # Returns
    ///
    /// Structured [`IpmiFenceError`].
    pub fn new(bmc_address: &str, completion_code: u8, reason: &str) -> Self {
        Self {
            bmc_address: bmc_address.to_owned(),
            completion_code,
            reason: reason.to_owned(),
        }
    }
}

/// Wrapper error for Tier-2 `NVMe` Persistent Reservation (`PROUT` Preempt-and-Abort) storage fencing failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display("NVMe reservation error on '{device_path}' (status 0x{nvme_status:04x}): {reason}")]
pub struct NvmeReservationError {
    /// Block or character device path (e.g., `"/dev/nvme0n1"`).
    pub device_path: String,
    /// 16-bit `NVMe` status code (e.g., `0x0083` Reservation Conflict).
    pub nvme_status: u16,
    /// Human-readable description of the `NVMe` reservation failure.
    pub reason: String,
}

impl NvmeReservationError {
    /// Creates a new [`NvmeReservationError`].
    ///
    /// # Arguments
    ///
    /// * `device_path` - Target `NVMe` device path.
    /// * `nvme_status` - Raw 16-bit `NVMe` status code.
    /// * `reason` - Diagnostic failure reason.
    ///
    /// # Returns
    ///
    /// Structured [`NvmeReservationError`].
    pub fn new(device_path: &str, nvme_status: u16, reason: &str) -> Self {
        Self {
            device_path: device_path.to_owned(),
            nvme_status,
            reason: reason.to_owned(),
        }
    }
}

/// Wrapper error for OCI Distribution Specification v1.1 image manifest and layer pull failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display(
    "OCI registry error on '{registry_uri}' (status {status_code}, digest '{digest}'): {reason}"
)]
pub struct OciRegistryError {
    /// OCI registry endpoint or image reference URI.
    pub registry_uri: String,
    /// HTTP status code returned by the registry.
    pub status_code: u16,
    /// Content digest (`sha256:...`) being fetched.
    pub digest: String,
    /// Human-readable failure reason.
    pub reason: String,
}

impl OciRegistryError {
    /// Creates a new [`OciRegistryError`].
    ///
    /// # Arguments
    ///
    /// * `registry_uri` - Target OCI registry URI.
    /// * `status_code` - HTTP status code.
    /// * `digest` - Layer or manifest digest string.
    /// * `reason` - Diagnostic failure reason.
    ///
    /// # Returns
    ///
    /// Structured [`OciRegistryError`].
    pub fn new(registry_uri: &str, status_code: u16, digest: &str, reason: &str) -> Self {
        Self {
            registry_uri: registry_uri.to_owned(),
            status_code,
            digest: digest.to_owned(),
            reason: reason.to_owned(),
        }
    }
}

/// Wrapper error for OpenTelemetry (`OTLP/HTTP`) metric and trace export failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error)]
#[display("OTLP export error on '{collector_endpoint}' (status {status_code}): {reason}")]
pub struct OtlpExportError {
    /// Target OTLP collector endpoint URI.
    pub collector_endpoint: String,
    /// HTTP status code returned by the collector.
    pub status_code: u16,
    /// Human-readable failure reason.
    pub reason: String,
}

impl OtlpExportError {
    /// Creates a new [`OtlpExportError`].
    ///
    /// # Arguments
    ///
    /// * `collector_endpoint` - Target OTLP collector endpoint URI.
    /// * `status_code` - HTTP status code.
    /// * `reason` - Diagnostic failure reason.
    ///
    /// # Returns
    ///
    /// Structured [`OtlpExportError`].
    pub fn new(collector_endpoint: &str, status_code: u16, reason: &str) -> Self {
        Self {
            collector_endpoint: collector_endpoint.to_owned(),
            status_code,
            reason: reason.to_owned(),
        }
    }
}

/// Comprehensive, strongly-typed error enum covering all failure modes in Arbiter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display, Error, From)]
pub enum ArbiterError {
    /// An identifier string was empty when a non-empty value was required.
    #[display("Empty identifier provided for kind '{kind}'")]
    EmptyIdentifier {
        /// The domain identifier kind that was empty.
        kind: String,
    },

    /// An identifier contained characters outside the permitted ASCII/URL-safe set or exceeded length bounds.
    #[display("Invalid identifier '{value}' for kind '{kind}': {reason}")]
    InvalidIdentifierCharacters {
        /// The domain identifier kind.
        kind: String,
        /// The rejected identifier value.
        value: String,
        /// Explanation of why the identifier is invalid.
        reason: String,
    },

    /// A resource quantity violated domain invariants (e.g., zero when positive required, or out of range).
    #[display("Invalid resource quantity {quantity} for '{resource}': {reason}")]
    InvalidResourceQuantity {
        /// Name of the resource type.
        resource: String,
        /// The invalid numeric value.
        quantity: u64,
        /// Reason the quantity is invalid.
        reason: String,
    },

    /// A numeric or port range had `start > end` or violated bounds.
    #[display("Invalid range bounds [{start}, {end}] for '{context}'")]
    InvalidRangeBounds {
        /// Context or type of the range.
        context: String,
        /// Start of the range.
        start: u64,
        /// End of the range.
        end: u64,
    },

    /// A hardware topology graph contained cycles, dangling edges, or invalid interconnect links.
    #[display("Invalid hardware topology graph: {reason}")]
    InvalidTopologyGraph {
        /// Detailed explanation of the topology violation.
        reason: String,
    },

    /// A role weight or basis point share was zero or exceeded the allowed maximum.
    #[display("Invalid share weight {weight_bps} bps: {reason}")]
    InvalidShareWeight {
        /// The rejected weight in basis points.
        weight_bps: u64,
        /// Explanation of the constraint violation.
        reason: String,
    },

    /// A role quota had guaranteed minimum exceeding hard maximum capacity.
    #[display("Invalid quota bounds for role '{role}': {reason}")]
    InvalidQuotaBounds {
        /// Name of the role.
        role: String,
        /// Description of the quota bound mismatch.
        reason: String,
    },

    /// Checked integer addition or multiplication overflowed `u64::MAX`.
    #[display("Arithmetic overflow during '{operation}'")]
    ArithmeticOverflow {
        /// Description of the arithmetic operation that overflowed.
        operation: String,
    },

    /// Checked integer subtraction underflowed below zero.
    #[display("Arithmetic underflow during '{operation}'")]
    ArithmeticUnderflow {
        /// Description of the arithmetic operation that underflowed.
        operation: String,
    },

    /// Checked integer division or remainder encountered a zero divisor.
    #[display("Division by zero during '{operation}'")]
    DivisionByZero {
        /// Description of the division operation.
        operation: String,
    },

    /// Requested resources exceed available capacity.
    #[display("Insufficient '{resource}': requested {requested}, available {available}")]
    InsufficientResources {
        /// The resource dimension that was exhausted.
        resource: String,
        /// Requested amount.
        requested: u64,
        /// Available amount.
        available: u64,
    },

    /// Attempted to combine or compare incompatible resource types.
    #[display("Resource type mismatch: expected '{expected}', found '{found}'")]
    ResourceTypeMismatch {
        /// Expected resource type or vendor.
        expected: String,
        /// Actual resource type or vendor encountered.
        found: String,
    },

    /// A hardware device ID was registered more than once in the same bundle or topology.
    #[display("Duplicate device ID '{device_id}'")]
    DuplicateDeviceId {
        /// The duplicated device identifier.
        device_id: String,
    },

    /// Referenced hardware device ID was not found.
    #[display("Device '{device_id}' not found")]
    DeviceNotFound {
        /// The missing device identifier.
        device_id: String,
    },

    /// An NVIDIA MIG profile slice configuration was invalid or unsupported.
    #[display("Invalid NVIDIA MIG profile '{profile}': {reason}")]
    InvalidMigProfile {
        /// The MIG profile string or identifier.
        profile: String,
        /// Reason the profile is invalid.
        reason: String,
    },

    /// A TPU topology slice specification had invalid torus dimensions or unhealthy ICI links.
    #[display("Invalid TPU topology slice '{slice}': {reason}")]
    InvalidTpuTopologySlice {
        /// Description or ID of the TPU slice.
        slice: String,
        /// Reason the slice is invalid.
        reason: String,
    },

    /// Hardware nodes cannot be linked via the requested interconnect fabric.
    #[display(
        "Incompatible interconnect '{interconnect}' between '{source_node}' and '{target_node}'"
    )]
    IncompatibleInterconnect {
        /// The interconnect type name.
        interconnect: String,
        /// Source node identifier.
        source_node: String,
        /// Target node identifier.
        target_node: String,
    },

    /// No registered agents satisfied the task's resource and topology constraints.
    #[display("No eligible agents found for workload '{workload}': {reason}")]
    NoEligibleAgents {
        /// Workload or task identifier.
        workload: String,
        /// Summary of why agents were filtered out.
        reason: String,
    },

    /// Atomic gang scheduling failed to place all members of a task group simultaneously.
    #[display(
        "Gang constraint unsatisfied for group '{group_id}': placed {placed}/{required} members"
    )]
    GangConstraintUnsatisfied {
        /// Task group identifier.
        group_id: String,
        /// Number of members that could be placed.
        placed: usize,
        /// Total members required for atomic gang launch.
        required: usize,
    },

    /// Preemption solver could not free sufficient topology-compatible capacity.
    #[display("Preemption failed for workload '{workload}': {reason}")]
    PreemptionFailed {
        /// Incoming high-priority workload identifier.
        workload: String,
        /// Reason preemption could not satisfy the request.
        reason: String,
    },

    /// Allocation would exceed the role's hard maximum quota.
    #[display("Quota exceeded for role '{role}' on resource '{resource}'")]
    QuotaExceeded {
        /// Role identifier.
        role: String,
        /// Resource dimension that exceeded quota.
        resource: String,
    },

    /// Referenced role does not exist in the hierarchy.
    #[display("Role '{role}' not found")]
    RoleNotFound {
        /// Missing role name.
        role: String,
    },

    /// Referenced framework ID is not registered.
    #[display("Framework '{framework_id}' not found")]
    FrameworkNotFound {
        /// Missing framework identifier.
        framework_id: String,
    },

    /// Resource offer TTL elapsed before acceptance.
    #[display("Offer '{offer_id}' has expired")]
    OfferExpired {
        /// Expired offer identifier.
        offer_id: String,
    },

    /// Resource offer was already accepted, declined, or rescinded.
    #[display("Offer '{offer_id}' was already consumed")]
    OfferAlreadyConsumed {
        /// Consumed offer identifier.
        offer_id: String,
    },

    /// State store read operation failed.
    #[display("State store read error on key '{key}': {reason}")]
    StoreReadError {
        /// Key or prefix being read.
        key: String,
        /// Failure reason.
        reason: String,
    },

    /// State store write or delete operation failed.
    #[display("State store write error on key '{key}': {reason}")]
    StoreWriteError {
        /// Key being mutated.
        key: String,
        /// Failure reason.
        reason: String,
    },

    /// Atomic Compare-And-Swap failed due to version or value mismatch.
    #[display("CAS conflict on key '{key}': expected revision {expected_rev}, actual {actual_rev}")]
    CasConflict {
        /// Key targeted by CAS.
        key: String,
        /// Expected revision or state description.
        expected_rev: u64,
        /// Actual revision encountered.
        actual_rev: u64,
    },

    /// Embedded Raft consensus protocol error.
    #[display("Raft consensus error in term {term}: {reason}")]
    RaftConsensusError {
        /// Current Raft term.
        term: u64,
        /// Reason for consensus failure.
        reason: String,
    },

    /// Mutating operation was submitted to a non-leader Raft node.
    #[display("Node '{node_id}' is not the Raft leader (known leader: '{leader_hint}')")]
    NotLeader {
        /// ID of the follower/candidate node that rejected the write.
        node_id: String,
        /// Optional hint of the current leader ID (empty if unknown).
        leader_hint: String,
    },

    /// Time-bounded election or heartbeat lease has expired.
    #[display("Lease '{lease_id}' expired at tick {expired_at_tick}")]
    LeaseExpired {
        /// Identifier of the expired lease.
        lease_id: String,
        /// Monotonic tick or timestamp when the lease expired.
        expired_at_tick: u64,
    },

    /// Operation presented a fencing token older than the current active epoch.
    #[display("Stale fencing token {presented_token} (minimum required: {current_token})")]
    FencingTokenStale {
        /// The rejected stale token value.
        presented_token: u64,
        /// The active monotonic fencing token value.
        current_token: u64,
    },

    /// Hardware or OS STONITH fencing action failed to execute cleanly.
    #[display("Fence execution failed on target '{target}': {reason}")]
    FenceExecutionFailed {
        /// Target agent or task being fenced.
        target: String,
        /// Failure details.
        reason: String,
    },

    /// Overlapping primary leases or conflicting quorum partitions were detected.
    #[display("Split-brain detected in election group '{group_id}': {details}")]
    SplitBrainDetected {
        /// Election group or cluster identifier.
        group_id: String,
        /// Diagnostic details of the conflict.
        details: String,
    },

    /// Remote federated cluster peer could not be reached.
    #[display("Federation peer '{peer_cluster}' is unreachable: {reason}")]
    FederationPeerUnreachable {
        /// Target peer cluster ID.
        peer_cluster: String,
        /// Connectivity failure reason.
        reason: String,
    },

    /// Wire or storage serialization failed.
    #[display("Serialization error ({format}): {reason}")]
    SerializationError {
        /// Format name (e.g., `rkyv`, `json`).
        format: String,
        /// Failure description.
        reason: String,
    },

    /// Wire or storage deserialization failed.
    #[display("Deserialization error ({format}): {reason}")]
    DeserializationError {
        /// Format name (e.g., `rkyv`, `json`).
        format: String,
        /// Failure description.
        reason: String,
    },

    /// JSON codec error automatically converted via `From<JsonCodecError>`.
    #[display("JSON codec failure: {_0}")]
    #[from]
    JsonCodec(JsonCodecError),

    /// Standard I/O operation error automatically converted via `From<IoOperationError>`.
    #[display("I/O failure: {_0}")]
    #[from]
    IoOperation(IoOperationError),

    /// Zero-copy `rkyv` binary codec error automatically converted via `From<RkyvCodecError>`.
    #[display("rkyv binary codec failure: {_0}")]
    #[from]
    RkyvCodec(RkyvCodecError),

    /// QUIC transport error automatically converted via `From<QuicTransportError>`.
    #[display("QUIC transport failure: {_0}")]
    #[from]
    QuicTransport(QuicTransportError),

    /// TLS 1.3 codec error automatically converted via `From<RustlsCodecError>`.
    #[display("TLS codec failure: {_0}")]
    #[from]
    RustlsCodec(RustlsCodecError),

    /// HTTP transport error automatically converted via `From<HttpTransportError>`.
    #[display("HTTP transport failure: {_0}")]
    #[from]
    HttpTransport(HttpTransportError),

    /// WebSocket codec error automatically converted via `From<WebSocketCodecError>`.
    #[display("WebSocket codec failure: {_0}")]
    #[from]
    WebSocketCodec(WebSocketCodecError),

    /// etcd v3 client error automatically converted via `From<EtcdClientError>`.
    #[display("etcd v3 client failure: {_0}")]
    #[from]
    EtcdClient(EtcdClientError),

    /// `PostgreSQL` client error automatically converted via `From<PostgresClientError>`.
    #[display("PostgreSQL client failure: {_0}")]
    #[from]
    PostgresClient(PostgresClientError),

    /// Tier-2 Out-of-Band Redfish BMC power fencing error automatically converted via `From<RedfishFenceError>`.
    #[display("Redfish BMC fence failure: {_0}")]
    #[from]
    RedfishFence(RedfishFenceError),

    /// Tier-2 Out-of-Band IPMI v2 chassis control error automatically converted via `From<IpmiFenceError>`.
    #[display("IPMI v2 fence failure: {_0}")]
    #[from]
    IpmiFence(IpmiFenceError),

    /// Tier-2 `NVMe` Persistent Reservation fencing error automatically converted via `From<NvmeReservationError>`.
    #[display("NVMe reservation failure: {_0}")]
    #[from]
    NvmeReservation(NvmeReservationError),

    /// OCI image registry pull error automatically converted via `From<OciRegistryError>`.
    #[display("OCI registry failure: {_0}")]
    #[from]
    OciRegistry(OciRegistryError),

    /// OpenTelemetry OTLP export error automatically converted via `From<OtlpExportError>`.
    #[display("OTLP export failure: {_0}")]
    #[from]
    OtlpExport(OtlpExportError),

    /// Multi-key state store transaction was aborted.
    #[display("Transaction aborted: {reason}")]
    TransactionAborted {
        /// Reason the transaction was rolled back.
        reason: String,
    },

    /// Generic network transport error.
    #[display("Transport error on '{endpoint}': {reason}")]
    TransportError {
        /// Endpoint address or stream identifier.
        endpoint: String,
        /// Reason for transport failure.
        reason: String,
    },

    /// QUIC connection or stream multiplexing error.
    #[display("QUIC connection error (stream {stream_id}): {reason}")]
    QuicConnectionError {
        /// QUIC stream identifier.
        stream_id: u64,
        /// Error description.
        reason: String,
    },

    /// HTTP/REST, SSE, or WebSocket handler error.
    #[display("HTTP handler error (status {status_code}): {message}")]
    HttpHandlerError {
        /// HTTP status code.
        status_code: u16,
        /// Diagnostic message.
        message: String,
    },

    /// mTLS certificate or TLS configuration error.
    #[display("TLS configuration error: {reason}")]
    TlsConfigurationError {
        /// Detailed TLS failure reason.
        reason: String,
    },

    /// SPIFFE workload identity URI SAN is malformed, untrusted, or expired.
    #[display("Invalid SPIFFE identity '{uri}': {reason}")]
    SpiffeIdentityInvalid {
        /// The rejected SPIFFE URI string.
        uri: String,
        /// Validation failure reason.
        reason: String,
    },

    /// OIDC/JWT or mTLS client authentication failed.
    #[display("Authentication failed for principal '{principal}': {reason}")]
    AuthenticationFailed {
        /// Principal identifier.
        principal: String,
        /// Failure reason.
        reason: String,
    },

    /// RBAC or ABAC policy engine denied the requested action.
    #[display(
        "Authorization denied for principal '{principal}' on action '{action}' targeting '{resource}'"
    )]
    AuthorizationDenied {
        /// Principal requesting access.
        principal: String,
        /// Requested action.
        action: String,
        /// Target resource.
        resource: String,
    },

    /// Envelope AEAD decryption of a task secret failed due to key mismatch or ciphertext tampering.
    #[display("Secret decryption failed for secret '{secret_id}': {reason}")]
    SecretDecryptionFailed {
        /// Secret identifier.
        secret_id: String,
        /// Failure reason.
        reason: String,
    },

    /// Requested OS isolator primitive is not supported on the host operating system.
    #[display("Isolator '{isolator}' is not supported on OS '{os}'")]
    IsolatorUnsupportedOnOs {
        /// Name of the isolation mechanism.
        isolator: String,
        /// Operating system name.
        os: String,
    },

    /// Linux `cgroups v2` hierarchy configuration or limit enforcement failed.
    #[display("Linux cgroup v2 error at '{cgroup_path}': {reason}")]
    CgroupError {
        /// Cgroup filesystem path.
        cgroup_path: String,
        /// Failure reason.
        reason: String,
    },

    /// Linux namespace or `seccomp-bpf` setup failed.
    #[display("Linux namespace error ({namespace_kind}): {reason}")]
    NamespaceError {
        /// Type of namespace (`pid`, `net`, `mnt`, etc.).
        namespace_kind: String,
        /// Failure reason.
        reason: String,
    },

    /// FreeBSD Jail or RCTL/RACCT resource limit operation failed.
    #[display("FreeBSD jail error for '{jail_name}': {reason}")]
    JailError {
        /// Jail name or JID.
        jail_name: String,
        /// Failure reason.
        reason: String,
    },

    /// illumos Zone, processor set (`pset`), or Crossbow VNIC operation failed.
    #[display("illumos zone error for '{zone_name}': {reason}")]
    ZoneError {
        /// Zone name.
        zone_name: String,
        /// Failure reason.
        reason: String,
    },

    /// Windows Job Object or Processor Group affinity operation failed.
    #[display("Windows Job Object error for '{job_name}': {reason}")]
    JobObjectError {
        /// Job Object identifier.
        job_name: String,
        /// Failure reason.
        reason: String,
    },

    /// macOS `sandbox-exec`, `setrlimit`, or Mach `QoS` policy operation failed.
    #[display("Sandbox error ({mechanism}): {reason}")]
    SandboxError {
        /// Underlying sandbox mechanism.
        mechanism: String,
        /// Failure reason.
        reason: String,
    },

    /// OCI container runtime (`runc`, `crun`, `containerd`, `ocijail`, `runhcs`) failed.
    #[display("Container runtime '{runtime}' error for container '{container_id}': {reason}")]
    ContainerRuntimeError {
        /// Runtime binary or driver name.
        runtime: String,
        /// Container identifier.
        container_id: String,
        /// Failure reason.
        reason: String,
    },

    /// `MicroVM` driver (`Firecracker`, `bhyve`, `Hyper-V`, `Virtualization.framework`) failed.
    #[display("MicroVM engine '{engine}' error for VM '{vm_id}': {reason}")]
    MicroVmError {
        /// `MicroVM` hypervisor name.
        engine: String,
        /// Virtual machine identifier.
        vm_id: String,
        /// Failure reason.
        reason: String,
    },

    /// OS user/group privilege drop or working directory switch failed.
    #[display("User switch error for user '{user}': {reason}")]
    UserSwitchError {
        /// Target OS username or UID.
        user: String,
        /// Failure reason.
        reason: String,
    },

    /// System CPU, NUMA, memory, or fabric hardware discovery probe failed.
    #[display("Hardware probe '{probe_name}' failed: {reason}")]
    ProbeFailed {
        /// Name of the hardware collector.
        probe_name: String,
        /// Failure reason.
        reason: String,
    },

    /// NVIDIA Management Library (NVML) probe or telemetry error.
    #[display("NVIDIA NVML error on device '{device}': {reason}")]
    NvmlError {
        /// GPU identifier or index.
        device: String,
        /// NVML error details.
        reason: String,
    },

    /// AMD `ROCm` / SMI probe or telemetry error.
    #[display("AMD ROCm error on device '{device}': {reason}")]
    RocmError {
        /// GPU identifier or index.
        device: String,
        /// `ROCm` error details.
        reason: String,
    },

    /// Apple Silicon Metal / `IOKit` GPU or Neural Engine probe error.
    #[display("Apple Metal probe error: {reason}")]
    MetalError {
        /// Error details.
        reason: String,
    },

    /// Intel Level Zero (XPU) probe or sub-device tile error.
    #[display("Intel Level Zero error on device '{device}': {reason}")]
    LevelZeroError {
        /// Device identifier.
        device: String,
        /// Error details.
        reason: String,
    },

    /// Google Cloud TPU or Edge TPU driver probe error.
    #[display("TPU driver error on device '{device}': {reason}")]
    TpuDriverError {
        /// TPU device path or ID.
        device: String,
        /// Error details.
        reason: String,
    },

    /// Prometheus or OpenTelemetry metric registration conflict.
    #[display("Metric registration error for '{metric_name}': {reason}")]
    MetricRegistrationError {
        /// Name of the metric.
        metric_name: String,
        /// Conflict or validation reason.
        reason: String,
    },

    /// Task readiness or liveness health probe failed beyond threshold.
    #[display(
        "Health check failed for task '{task_id}' after {consecutive_failures} attempts: {reason}"
    )]
    HealthCheckFailed {
        /// Task identifier.
        task_id: String,
        /// Number of consecutive probe failures.
        consecutive_failures: u32,
        /// Diagnostic failure message.
        reason: String,
    },

    /// Command-line interface argument parsing or subcommand dispatch error.
    #[display("Invalid CLI arguments: {reason}")]
    InvalidCliArguments {
        /// Description of the invalid flag or argument.
        reason: String,
    },

    /// Graceful shutdown signal handler registration or execution error.
    #[display("Shutdown signal error: {reason}")]
    ShutdownSignalError {
        /// Error details.
        reason: String,
    },

    /// Invalid state machine transition for a task lifecycle.
    #[display("Invalid task state transition from '{from_state}' to '{to_state}'")]
    TaskStateTransitionInvalid {
        /// Current state name.
        from_state: String,
        /// Attempted target state name.
        to_state: String,
    },

    /// Benchmark or simulation configuration parameter violated domain invariants.
    #[display("Invalid benchmark configuration for '{parameter}': {reason}")]
    InvalidBenchmarkConfig {
        /// Name of the invalid benchmark parameter.
        parameter: String,
        /// Explanation of why the configuration is invalid.
        reason: String,
    },

    /// Active client transactional ledger detected a lost committed write or divergent history.
    #[display(
        "Linearizability violation in group '{group_id}': lost_writes={lost_writes}, divergent_writes={divergent_writes}"
    )]
    LinearizabilityViolation {
        /// Election group or service identifier.
        group_id: String,
        /// Count of acknowledged client writes missing after failover.
        lost_writes: u64,
        /// Count of split-brain or divergent writes detected.
        divergent_writes: u64,
    },

    /// Wire-traffic simulation model drifted beyond the allowed basis-point threshold from empirical capture.
    #[display(
        "Wire-traffic calibration drift {observed_drift_bps} bps exceeded maximum allowed {max_allowed_bps} bps"
    )]
    CalibrationDriftExceeded {
        /// Observed drift in basis points.
        observed_drift_bps: u64,
        /// Maximum permitted drift in basis points.
        max_allowed_bps: u64,
    },

    /// Failed to bind a TCP, UDP, or Unix Domain Socket listener endpoint.
    #[display("Socket bind error on '{endpoint}': {reason}")]
    SocketBindError {
        /// Endpoint address or UDS path.
        endpoint: String,
        /// Operating system or validation failure reason.
        reason: String,
    },

    /// Read or write operation on an open network or IPC socket failed.
    #[display("Socket I/O error on '{endpoint}': {reason}")]
    SocketIoError {
        /// Endpoint address or stream identifier.
        endpoint: String,
        /// Operating system I/O failure reason.
        reason: String,
    },

    /// X.509 certificate chain, validity window, or URI Subject Alternative Name validation failed.
    #[display("X.509 certificate validation error for '{subject}': {reason}")]
    X509ValidationError {
        /// Subject or URI SAN being verified.
        subject: String,
        /// Validation failure reason.
        reason: String,
    },

    /// Operating system child process creation (`fork`/`exec`/`CreateProcess`) failed.
    #[display("Failed to spawn process '{command}': {reason}")]
    ProcessSpawnError {
        /// Executable command or path.
        command: String,
        /// OS failure reason.
        reason: String,
    },

    /// Delivering a signal (`SIGTERM`, `SIGKILL`, `SIGUSR1`) or Job Object termination to a PID failed.
    #[display("Failed to deliver signal '{signal}' to PID {pid}: {reason}")]
    ProcessSignalError {
        /// Target OS process identifier.
        pid: u32,
        /// Signal name or number.
        signal: String,
        /// OS failure reason.
        reason: String,
    },

    /// Container Storage Interface (`CSI` v1.9) controller or node RPC failed.
    #[display("CSI RPC '{method}' failed for volume '{volume_id}': {reason}")]
    CsiRpcError {
        /// CSI gRPC method name (`NodeStageVolume`, `NodePublishVolume`, etc.).
        method: String,
        /// Target volume identifier.
        volume_id: String,
        /// Plugin failure reason.
        reason: String,
    },

    /// Cluster DNS or SRV service discovery resolution failed.
    #[display("DNS resolution error for '{fqdn}': {reason}")]
    DnsResolutionError {
        /// Queried fully-qualified domain name.
        fqdn: String,
        /// Resolution failure reason.
        reason: String,
    },

    /// Archive extraction or sandbox path materialization failed.
    #[display("Archive extraction error for '{archive}': {reason}")]
    ArchiveExtractionError {
        /// Archive URI or file name.
        archive: String,
        /// Extraction or path security failure reason.
        reason: String,
    },

    /// ASN.1 DER or PEM X.509v3 certificate parsing failed.
    #[display("X.509 ASN.1 parse error in '{context}': {reason}")]
    X509Asn1ParseError {
        /// Certificate section or extension OID context.
        context: String,
        /// Detailed ASN.1 decoding failure reason.
        reason: String,
    },

    /// Asymmetric cryptographic signature creation or verification (`Ed25519` / `ECDSA-P256`) failed.
    #[display("Cryptographic signature error ({algorithm}): {reason}")]
    CryptographicSignatureError {
        /// Signature algorithm name (`EdDSA`, `ES256`, `HS256`).
        algorithm: String,
        /// Verification or signing failure reason.
        reason: String,
    },

    /// Hardware watchdog device (`/dev/watchdog`) open, pet, or timeout operation failed.
    #[display("Hardware watchdog device error on '{device_path}': {reason}")]
    WatchdogDeviceError {
        /// Watchdog device path (e.g., `"/dev/watchdog"`).
        device_path: String,
        /// Device I/O or timeout failure reason.
        reason: String,
    },

    /// UDP or TCP RFC 1035 DNS wire packet parsing or encoding failed.
    #[display("DNS wire protocol error for '{query_name}': {reason}")]
    DnsProtocolError {
        /// Queried DNS label or packet context.
        query_name: String,
        /// Wire format error reason.
        reason: String,
    },
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::*;

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_all_error_variants_display_and_source() {
        let variants: Vec<ArbiterError> = vec![
            ArbiterError::EmptyIdentifier {
                kind: "AgentId".to_owned(),
            },
            ArbiterError::InvalidIdentifierCharacters {
                kind: "TaskId".to_owned(),
                value: "bad id!".to_owned(),
                reason: "contains spaces".to_owned(),
            },
            ArbiterError::InvalidResourceQuantity {
                resource: "cpu".to_owned(),
                quantity: 0,
                reason: "must be positive".to_owned(),
            },
            ArbiterError::InvalidRangeBounds {
                context: "PortRange".to_owned(),
                start: 9000,
                end: 8000,
            },
            ArbiterError::InvalidTopologyGraph {
                reason: "cycle detected".to_owned(),
            },
            ArbiterError::InvalidShareWeight {
                weight_bps: 0,
                reason: "weight cannot be zero".to_owned(),
            },
            ArbiterError::InvalidQuotaBounds {
                role: "prod".to_owned(),
                reason: "min > max".to_owned(),
            },
            ArbiterError::ArithmeticOverflow {
                operation: "Millicores::checked_add".to_owned(),
            },
            ArbiterError::ArithmeticUnderflow {
                operation: "Bytes::checked_sub".to_owned(),
            },
            ArbiterError::DivisionByZero {
                operation: "SharePartsPerBillion::from_ratio".to_owned(),
            },
            ArbiterError::InsufficientResources {
                resource: "memory".to_owned(),
                requested: 1024,
                available: 512,
            },
            ArbiterError::ResourceTypeMismatch {
                expected: "Nvidia".to_owned(),
                found: "Amd".to_owned(),
            },
            ArbiterError::DuplicateDeviceId {
                device_id: "gpu-0".to_owned(),
            },
            ArbiterError::DeviceNotFound {
                device_id: "gpu-9".to_owned(),
            },
            ArbiterError::InvalidMigProfile {
                profile: "9g.99gb".to_owned(),
                reason: "unknown profile".to_owned(),
            },
            ArbiterError::InvalidTpuTopologySlice {
                slice: "v5p-3x3".to_owned(),
                reason: "non-contiguous torus".to_owned(),
            },
            ArbiterError::IncompatibleInterconnect {
                interconnect: "NvLink".to_owned(),
                source_node: "cpu-0".to_owned(),
                target_node: "nic-0".to_owned(),
            },
            ArbiterError::NoEligibleAgents {
                workload: "job-1".to_owned(),
                reason: "no TPU v5p available".to_owned(),
            },
            ArbiterError::GangConstraintUnsatisfied {
                group_id: "gang-1".to_owned(),
                placed: 2,
                required: 4,
            },
            ArbiterError::PreemptionFailed {
                workload: "urgent-1".to_owned(),
                reason: "all tasks non-preemptible".to_owned(),
            },
            ArbiterError::QuotaExceeded {
                role: "analytics".to_owned(),
                resource: "gpu".to_owned(),
            },
            ArbiterError::RoleNotFound {
                role: "unknown-role".to_owned(),
            },
            ArbiterError::FrameworkNotFound {
                framework_id: "fw-99".to_owned(),
            },
            ArbiterError::OfferExpired {
                offer_id: "offer-1".to_owned(),
            },
            ArbiterError::OfferAlreadyConsumed {
                offer_id: "offer-2".to_owned(),
            },
            ArbiterError::StoreReadError {
                key: "/agents/1".to_owned(),
                reason: "disk read error".to_owned(),
            },
            ArbiterError::StoreWriteError {
                key: "/tasks/1".to_owned(),
                reason: "read-only filesystem".to_owned(),
            },
            ArbiterError::CasConflict {
                key: "/leader".to_owned(),
                expected_rev: 3,
                actual_rev: 4,
            },
            ArbiterError::RaftConsensusError {
                term: 12,
                reason: "quorum lost".to_owned(),
            },
            ArbiterError::NotLeader {
                node_id: "master-2".to_owned(),
                leader_hint: "master-1".to_owned(),
            },
            ArbiterError::LeaseExpired {
                lease_id: "lease-10".to_owned(),
                expired_at_tick: 500,
            },
            ArbiterError::FencingTokenStale {
                presented_token: 41,
                current_token: 42,
            },
            ArbiterError::FenceExecutionFailed {
                target: "agent-3".to_owned(),
                reason: "zone halt timed out".to_owned(),
            },
            ArbiterError::SplitBrainDetected {
                group_id: "pg-ha".to_owned(),
                details: "two active primaries".to_owned(),
            },
            ArbiterError::FederationPeerUnreachable {
                peer_cluster: "us-west-2".to_owned(),
                reason: "connection timed out".to_owned(),
            },
            ArbiterError::SerializationError {
                format: "rkyv".to_owned(),
                reason: "buffer full".to_owned(),
            },
            ArbiterError::DeserializationError {
                format: "json".to_owned(),
                reason: "unexpected EOF".to_owned(),
            },
            ArbiterError::TransactionAborted {
                reason: "conflicting key write".to_owned(),
            },
            ArbiterError::TransportError {
                endpoint: "127.0.0.1:5050".to_owned(),
                reason: "connection reset".to_owned(),
            },
            ArbiterError::QuicConnectionError {
                stream_id: 7,
                reason: "stream closed".to_owned(),
            },
            ArbiterError::HttpHandlerError {
                status_code: 400,
                message: "bad request".to_owned(),
            },
            ArbiterError::TlsConfigurationError {
                reason: "expired certificate".to_owned(),
            },
            ArbiterError::SpiffeIdentityInvalid {
                uri: "http://bad".to_owned(),
                reason: "scheme must be spiffe://".to_owned(),
            },
            ArbiterError::AuthenticationFailed {
                principal: "user-1".to_owned(),
                reason: "invalid signature".to_owned(),
            },
            ArbiterError::AuthorizationDenied {
                principal: "user-1".to_owned(),
                action: "LaunchTask".to_owned(),
                resource: "role:prod".to_owned(),
            },
            ArbiterError::SecretDecryptionFailed {
                secret_id: "sec-1".to_owned(),
                reason: "authentication tag mismatch".to_owned(),
            },
            ArbiterError::IsolatorUnsupportedOnOs {
                isolator: "FreeBsdJail".to_owned(),
                os: "Linux".to_owned(),
            },
            ArbiterError::CgroupError {
                cgroup_path: "/sys/fs/cgroup/arbiter".to_owned(),
                reason: "permission denied".to_owned(),
            },
            ArbiterError::NamespaceError {
                namespace_kind: "CLONE_NEWNET".to_owned(),
                reason: "EINVAL".to_owned(),
            },
            ArbiterError::JailError {
                jail_name: "arbiter_task_1".to_owned(),
                reason: "jail_set failed".to_owned(),
            },
            ArbiterError::ZoneError {
                zone_name: "zone_task_1".to_owned(),
                reason: "zoneadm boot failed".to_owned(),
            },
            ArbiterError::JobObjectError {
                job_name: "job_task_1".to_owned(),
                reason: "SetInformationJobObject failed".to_owned(),
            },
            ArbiterError::SandboxError {
                mechanism: "sandbox-exec".to_owned(),
                reason: "profile syntax error".to_owned(),
            },
            ArbiterError::ContainerRuntimeError {
                runtime: "crun".to_owned(),
                container_id: "c-1".to_owned(),
                reason: "rootfs missing".to_owned(),
            },
            ArbiterError::MicroVmError {
                engine: "bhyve".to_owned(),
                vm_id: "vm-1".to_owned(),
                reason: "vmm.ko not loaded".to_owned(),
            },
            ArbiterError::UserSwitchError {
                user: "nobody".to_owned(),
                reason: "setgid failed".to_owned(),
            },
            ArbiterError::ProbeFailed {
                probe_name: "LinuxSysfsProbe".to_owned(),
                reason: "/sys not mounted".to_owned(),
            },
            ArbiterError::NvmlError {
                device: "GPU-0".to_owned(),
                reason: "driver not loaded".to_owned(),
            },
            ArbiterError::RocmError {
                device: "card0".to_owned(),
                reason: "kfd unavailable".to_owned(),
            },
            ArbiterError::MetalError {
                reason: "no Metal device".to_owned(),
            },
            ArbiterError::LevelZeroError {
                device: "ze0".to_owned(),
                reason: "zeInit failed".to_owned(),
            },
            ArbiterError::TpuDriverError {
                device: "/dev/accel0".to_owned(),
                reason: "busy".to_owned(),
            },
            ArbiterError::MetricRegistrationError {
                metric_name: "arbiter_cpu_total".to_owned(),
                reason: "already registered".to_owned(),
            },
            ArbiterError::HealthCheckFailed {
                task_id: "task-1".to_owned(),
                consecutive_failures: 3,
                reason: "connection refused".to_owned(),
            },
            ArbiterError::InvalidCliArguments {
                reason: "unknown flag --foo".to_owned(),
            },
            ArbiterError::ShutdownSignalError {
                reason: "signal handler failed".to_owned(),
            },
            ArbiterError::TaskStateTransitionInvalid {
                from_state: "Finished".to_owned(),
                to_state: "Running".to_owned(),
            },
            ArbiterError::InvalidBenchmarkConfig {
                parameter: "NodeCount".to_owned(),
                reason: "must be non-zero".to_owned(),
            },
            ArbiterError::LinearizabilityViolation {
                group_id: "pg-ha".to_owned(),
                lost_writes: 1,
                divergent_writes: 0,
            },
            ArbiterError::CalibrationDriftExceeded {
                observed_drift_bps: 650,
                max_allowed_bps: 500,
            },
            ArbiterError::SocketBindError {
                endpoint: "0.0.0.0:5050".to_owned(),
                reason: "address in use".to_owned(),
            },
            ArbiterError::SocketIoError {
                endpoint: "127.0.0.1:5050".to_owned(),
                reason: "broken pipe".to_owned(),
            },
            ArbiterError::X509ValidationError {
                subject: "spiffe://arbiter.internal/node/a1".to_owned(),
                reason: "certificate expired".to_owned(),
            },
            ArbiterError::ProcessSpawnError {
                command: "/bin/nonexistent".to_owned(),
                reason: "ENOENT".to_owned(),
            },
            ArbiterError::ProcessSignalError {
                pid: 4242,
                signal: "SIGKILL".to_owned(),
                reason: "ESRCH".to_owned(),
            },
            ArbiterError::CsiRpcError {
                method: "NodePublishVolume".to_owned(),
                volume_id: "vol-1".to_owned(),
                reason: "socket timeout".to_owned(),
            },
            ArbiterError::DnsResolutionError {
                fqdn: "pg-0.db.arbiter.internal".to_owned(),
                reason: "NXDOMAIN".to_owned(),
            },
            ArbiterError::ArchiveExtractionError {
                archive: "bundle.tar.zst".to_owned(),
                reason: "corrupt header".to_owned(),
            },
            ArbiterError::X509Asn1ParseError {
                context: "OID 2.5.29.17".to_owned(),
                reason: "truncated DER tag".to_owned(),
            },
            ArbiterError::CryptographicSignatureError {
                algorithm: "EdDSA".to_owned(),
                reason: "invalid Ed25519 curve point".to_owned(),
            },
            ArbiterError::WatchdogDeviceError {
                device_path: "/dev/watchdog".to_owned(),
                reason: "watchdog timer expired".to_owned(),
            },
            ArbiterError::DnsProtocolError {
                query_name: "pg-0.db.prod.arbiter.internal".to_owned(),
                reason: "truncated DNS header".to_owned(),
            },
        ];

        for err in &variants {
            let msg = err.to_string();
            assert!(!msg.is_empty());
            assert!(err.source().is_none());
            let cloned = err.clone();
            assert_eq!(&cloned, err);
        }
    }

    #[test]
    fn test_json_codec_error_conversion_and_source() {
        let serde_err: serde_json::Error = serde::de::Error::custom("malformed json payload");
        let codec_err = JsonCodecError::from(serde_err);
        assert!(codec_err.to_string().contains("JSON codec error:"));
        assert!(std::error::Error::source(&codec_err).is_none());

        let arbiter_err = ArbiterError::from(codec_err);
        assert!(arbiter_err.to_string().contains("JSON codec failure:"));
        assert!(std::error::Error::source(&arbiter_err).is_some());

        let io_err = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "socket closed");
        let io_wrap = IoOperationError::from(io_err);
        assert!(io_wrap.to_string().contains("BrokenPipe"));
        assert!(std::error::Error::source(&io_wrap).is_none());
        let arbiter_io = ArbiterError::from(io_wrap);
        assert!(arbiter_io.to_string().contains("I/O failure:"));
        assert!(std::error::Error::source(&arbiter_io).is_some());

        let rkyv_err = <rkyv::rancor::Error as rkyv::rancor::Source>::new(IoOperationError {
            kind: "InvalidData".to_owned(),
            message: "bad archive".to_owned(),
        });
        let rkyv_wrap = RkyvCodecError::from(rkyv_err);
        assert!(rkyv_wrap.to_string().contains("rkyv binary codec error:"));
        assert!(std::error::Error::source(&rkyv_wrap).is_none());
        let arbiter_rkyv = ArbiterError::from(rkyv_wrap);
        assert!(
            arbiter_rkyv
                .to_string()
                .contains("rkyv binary codec failure:")
        );
        assert!(std::error::Error::source(&arbiter_rkyv).is_some());
    }

    #[test]
    #[allow(clippy::cognitive_complexity, clippy::too_many_lines)]
    fn test_transport_and_store_wrapper_errors() {
        let quic_wrap = QuicTransportError::new(1, "stream reset");
        assert!(quic_wrap.to_string().contains("QUIC transport error"));
        assert!(std::error::Error::source(&quic_wrap).is_none());
        let arbiter_quic = ArbiterError::from(quic_wrap);
        assert!(arbiter_quic.to_string().contains("QUIC transport failure:"));
        assert!(std::error::Error::source(&arbiter_quic).is_some());

        let tls_wrap = RustlsCodecError::new("bad certificate");
        assert!(tls_wrap.to_string().contains("TLS codec error:"));
        assert!(std::error::Error::source(&tls_wrap).is_none());
        let arbiter_tls = ArbiterError::from(tls_wrap);
        assert!(arbiter_tls.to_string().contains("TLS codec failure:"));
        assert!(std::error::Error::source(&arbiter_tls).is_some());

        let http_wrap = HttpTransportError::new(502, "bad gateway");
        assert!(http_wrap.to_string().contains("HTTP transport error"));
        assert!(std::error::Error::source(&http_wrap).is_none());
        let arbiter_http = ArbiterError::from(http_wrap);
        assert!(arbiter_http.to_string().contains("HTTP transport failure:"));
        assert!(std::error::Error::source(&arbiter_http).is_some());

        let ws_wrap = WebSocketCodecError::new("invalid frame mask");
        assert!(ws_wrap.to_string().contains("WebSocket codec error:"));
        assert!(std::error::Error::source(&ws_wrap).is_none());
        let arbiter_ws = ArbiterError::from(ws_wrap);
        assert!(arbiter_ws.to_string().contains("WebSocket codec failure:"));
        assert!(std::error::Error::source(&arbiter_ws).is_some());

        let etcd_wrap = EtcdClientError::new("http://127.0.0.1:2379", "unavailable");
        assert!(etcd_wrap.to_string().contains("etcd v3 client error"));
        assert!(std::error::Error::source(&etcd_wrap).is_none());
        let arbiter_etcd = ArbiterError::from(etcd_wrap);
        assert!(arbiter_etcd.to_string().contains("etcd v3 client failure:"));
        assert!(std::error::Error::source(&arbiter_etcd).is_some());

        let pg_wrap = PostgresClientError::new("40001", "serialization_failure");
        assert!(pg_wrap.to_string().contains("PostgreSQL client error"));
        assert!(std::error::Error::source(&pg_wrap).is_none());
        let arbiter_pg = ArbiterError::from(pg_wrap);
        assert!(
            arbiter_pg
                .to_string()
                .contains("PostgreSQL client failure:")
        );
        assert!(std::error::Error::source(&arbiter_pg).is_some());

        let redfish_wrap = RedfishFenceError::new("https://bmc.node1/redfish/v1", 503, "BMC busy");
        assert!(redfish_wrap.to_string().contains("Redfish BMC fence error"));
        assert!(std::error::Error::source(&redfish_wrap).is_none());
        let arbiter_redfish = ArbiterError::from(redfish_wrap);
        assert!(
            arbiter_redfish
                .to_string()
                .contains("Redfish BMC fence failure:")
        );
        assert!(std::error::Error::source(&arbiter_redfish).is_some());

        let ipmi_wrap = IpmiFenceError::new("10.0.0.10:623", 0xC0, "Node Busy");
        assert!(ipmi_wrap.to_string().contains("IPMI v2 fence error"));
        assert!(std::error::Error::source(&ipmi_wrap).is_none());
        let arbiter_ipmi = ArbiterError::from(ipmi_wrap);
        assert!(arbiter_ipmi.to_string().contains("IPMI v2 fence failure:"));
        assert!(std::error::Error::source(&arbiter_ipmi).is_some());

        let nvme_wrap = NvmeReservationError::new("/dev/nvme0n1", 0x0083, "Reservation Conflict");
        assert!(nvme_wrap.to_string().contains("NVMe reservation error"));
        assert!(std::error::Error::source(&nvme_wrap).is_none());
        let arbiter_nvme = ArbiterError::from(nvme_wrap);
        assert!(
            arbiter_nvme
                .to_string()
                .contains("NVMe reservation failure:")
        );
        assert!(std::error::Error::source(&arbiter_nvme).is_some());

        let oci_wrap = OciRegistryError::new(
            "https://registry-1.docker.io",
            404,
            "sha256:deadbeef",
            "manifest unknown",
        );
        assert!(oci_wrap.to_string().contains("OCI registry error"));
        assert!(std::error::Error::source(&oci_wrap).is_none());
        let arbiter_oci = ArbiterError::from(oci_wrap);
        assert!(arbiter_oci.to_string().contains("OCI registry failure:"));
        assert!(std::error::Error::source(&arbiter_oci).is_some());

        let otlp_wrap =
            OtlpExportError::new("http://127.0.0.1:4318/v1/metrics", 502, "collector down");
        assert!(otlp_wrap.to_string().contains("OTLP export error"));
        assert!(std::error::Error::source(&otlp_wrap).is_none());
        let arbiter_otlp = ArbiterError::from(otlp_wrap);
        assert!(arbiter_otlp.to_string().contains("OTLP export failure:"));
        assert!(std::error::Error::source(&arbiter_otlp).is_some());
    }
}
