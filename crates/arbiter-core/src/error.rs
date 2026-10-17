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
    }
}
