//! Zero-copy binary wire schemas (`rkyv`) and HTTP/JSON DTOs (`serde`) for Arbiter (`arbiter-proto`).
//!
//! Defines versioned protocol envelopes for Master $\leftrightarrow$ Agent and Master $\leftrightarrow$ Framework
//! QUIC streams as well as Mesos v1-style HTTP/REST/SSE operator, scheduler, executor, and job APIs.

#![forbid(missing_docs)]
#![forbid(clippy::missing_docs_in_private_items)]

use arbiter_core::error::{ArbiterError, ArbiterResult, JsonCodecError};
use arbiter_core::ids::{AgentId, FrameworkId, OfferId, RoleName, TaskId};
use arbiter_core::platform::{CpuArch, OsKind};
use arbiter_core::resources::ResourceBundle;
use arbiter_core::topology::HardwareTopologyGraph;
use arbiter_core::units::{PowerMilliwatts, TemperatureMilliCelsius};
use arbiter_core::workload::{
    OfferOperation, PreemptionPolicy, ResourceOffer, TaskGroupSpec, TaskSpec, TaskState,
};
use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use serde::{Deserialize, Serialize};

/// Current wire protocol schema version (`1`).
pub const WIRE_SCHEMA_VERSION: u16 = 1;

/// Agent registration message sent over QUIC or HTTP (`/api/v1/executor` / control stream).
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize,
)]
#[rkyv(derive(Debug))]
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
#[rkyv(compare(PartialEq), derive(Debug))]
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
#[rkyv(compare(PartialEq), derive(Debug))]
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
#[rkyv(compare(PartialEq), derive(Debug))]
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
#[rkyv(compare(PartialEq), derive(Debug))]
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
#[rkyv(compare(PartialEq), derive(Debug))]
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
#[rkyv(compare(PartialEq), derive(Debug))]
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
#[rkyv(compare(PartialEq), derive(Debug))]
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
#[rkyv(compare(PartialEq), derive(Debug))]
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
#[rkyv(compare(PartialEq), derive(Debug))]
pub enum SubmitDirectJob {
    /// Single standalone task.
    SingleTask(Box<TaskSpec>),
    /// Atomic gang-scheduled task group.
    GangJob(TaskGroupSpec),
}

/// Unified control-plane wire message payload.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize,
)]
#[rkyv(derive(Debug))]
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
    PreemptTaskCommand(PreemptTaskCommand),
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
}

/// Versioned wire envelope wrapping any [`WireMessage`] for binary (`rkyv`) or JSON (`serde`) transport.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize,
)]
#[rkyv(derive(Debug))]
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

    /// Encodes this [`WireEnvelope`] into zero-copy `rkyv` binary bytes.
    ///
    /// # Returns
    ///
    /// Binary payload `Vec<u8>`.
    pub fn to_rkyv_bytes(&self) -> Vec<u8> {
        rkyv::to_bytes::<rkyv::rancor::Error>(self)
            .map(rkyv::util::AlignedVec::into_vec)
            .unwrap_or_default()
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
    /// Returns [`ArbiterError::DeserializationError`] if the byte slice fails `rkyv` bytecheck
    /// validation or has an unsupported `version`.
    pub fn from_rkyv_bytes(bytes: &[u8]) -> ArbiterResult<Self> {
        let mut aligned = rkyv::util::AlignedVec::<16>::with_capacity(bytes.len());
        aligned.extend_from_slice(bytes);
        let decoded: Self =
            rkyv::from_bytes::<Self, rkyv::rancor::Error>(&aligned).map_err(|err| {
                ArbiterError::DeserializationError {
                    format: "rkyv".to_owned(),
                    reason: err.to_string(),
                }
            })?;
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
        ];
        for (path, expected) in endpoints {
            assert_eq!(ApiEndpoint::from_path(path), Ok(expected));
            assert_eq!(expected.as_path(), path);
        }
        assert!(ApiEndpoint::from_path("/api/v1/unknown").is_err());
    }

    #[test]
    fn test_rkyv_and_json_roundtrip_and_version_validation() {
        let hb = WireMessage::AgentHeartbeat(AgentHeartbeat {
            agent_id: AgentId::new("agent-1").unwrap_or_default(),
            tick: 42,
            healthy_tasks: vec![TaskId::new("t-1").unwrap_or_default()],
        });
        let env = WireEnvelope::new(100, hb);

        // rkyv roundtrip
        let bin = env.to_rkyv_bytes();
        assert_eq!(WireEnvelope::from_rkyv_bytes(&bin), Ok(env.clone()));

        // Corrupted binary payload rejected
        assert!(WireEnvelope::from_rkyv_bytes(b"corrupted").is_err());

        // Unsupported version in rkyv rejected
        let mut bad_ver = env.clone();
        bad_ver.version = 99;
        let bad_bin = bad_ver.to_rkyv_bytes();
        assert!(WireEnvelope::from_rkyv_bytes(&bad_bin).is_err());

        // JSON roundtrip
        let json = env.to_json_string();
        assert_eq!(WireEnvelope::from_json_str(&json), Ok(env));

        // Malformed JSON rejected
        assert!(WireEnvelope::from_json_str("{bad").is_err());

        // Unsupported version in JSON rejected
        let bad_json = bad_ver.to_json_string();
        assert!(WireEnvelope::from_json_str(&bad_json).is_err());
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
