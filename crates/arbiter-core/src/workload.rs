//! Workload specifications, task state machine, hierarchical roles, quotas, and resource offers.
//!
//! Models both Mesos 2-level `ResourceOffer` / `OfferOperation` workflows and direct task /
//! gang-scheduled (`TaskGroupSpec`) workloads with strict state transition validation.

use core::fmt;

use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use serde::{Deserialize, Serialize};

use crate::error::{ArbiterError, ArbiterResult};
use crate::ids::{
    AgentId, ElectionGroupId, ExecutorId, FrameworkId, OfferId, QuotaId, RoleName, SecretId,
    TaskGroupId, TaskId, VolumeId,
};
use crate::platform::IsolationCapability;
use crate::resources::{GpuPartition, GpuVendor, ResourceBundle, TpuTopologySlice};
use crate::units::{Bytes, PortNumber, WeightBasisPoints};

/// Resource quota policy attached to a [`Role`].
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct Quota {
    /// Unique identifier for this quota policy.
    pub id: QuotaId,
    /// Guaranteed minimum resource bundle reserved for this role.
    pub guaranteed_min: ResourceBundle,
    /// Hard maximum resource bundle this role may consume.
    pub hard_max: ResourceBundle,
    /// Whether this role is allowed to burst above `guaranteed_min` up to `hard_max` using idle cluster capacity.
    pub allow_burst_borrowing: bool,
    /// Relative HDRF fairness weight in basis points.
    pub weight: WeightBasisPoints,
}

impl Quota {
    /// Validates and constructs a [`Quota`] policy, ensuring `hard_max` contains `guaranteed_min`.
    ///
    /// # Arguments
    ///
    /// * `id` - Unique [`QuotaId`].
    /// * `role` - Target [`RoleName`] for error diagnostics.
    /// * `guaranteed_min` - Guaranteed minimum [`ResourceBundle`].
    /// * `hard_max` - Hard ceiling [`ResourceBundle`].
    /// * `allow_burst_borrowing` - Whether idle quota borrowing is permitted.
    /// * `weight` - Fair share [`WeightBasisPoints`].
    ///
    /// # Returns
    ///
    /// Validated [`Quota`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::InvalidQuotaBounds`] if `hard_max` does not contain `guaranteed_min`.
    pub fn new(
        id: QuotaId,
        role: &RoleName,
        guaranteed_min: ResourceBundle,
        hard_max: ResourceBundle,
        allow_burst_borrowing: bool,
        weight: WeightBasisPoints,
    ) -> ArbiterResult<Self> {
        if !hard_max.contains(&guaranteed_min) {
            return Err(ArbiterError::InvalidQuotaBounds {
                role: role.to_string(),
                reason: "hard_max bundle must be >= guaranteed_min on all resource dimensions"
                    .to_owned(),
            });
        }
        Ok(Self {
            id,
            guaranteed_min,
            hard_max,
            allow_burst_borrowing,
            weight,
        })
    }
}

/// Scheduling role node within a [`RoleHierarchy`].
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct Role {
    /// Role name (e.g., `"prod"`, `"prod.ml"`, `"batch.analytics"`).
    pub name: RoleName,
    /// Optional parent role name (`None` for top-level roles under root).
    pub parent: Option<RoleName>,
    /// Quota and weight policy for this role.
    pub quota: Quota,
}

/// Tree of hierarchical scheduling roles.
#[derive(
    Debug,
    Default,
    Clone,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
)]
#[rkyv(derive(Debug))]
pub struct RoleHierarchy {
    /// Registered roles in deterministic order.
    roles: Vec<Role>,
}

impl RoleHierarchy {
    /// Creates an empty [`RoleHierarchy`].
    ///
    /// # Returns
    ///
    /// Empty [`RoleHierarchy`].
    pub const fn new() -> Self {
        Self { roles: Vec::new() }
    }

    /// Registers a [`Role`] in the hierarchy.
    ///
    /// If `role.parent` is `Some`, the parent role must already be registered.
    ///
    /// # Arguments
    ///
    /// * `role` - The [`Role`] to insert.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::RoleNotFound`] if the specified parent role is not present, or
    /// [`ArbiterError::InvalidQuotaBounds`] if a role with the same name already exists.
    pub fn add_role(&mut self, role: Role) -> ArbiterResult<()> {
        if self.roles.iter().any(|r| r.name == role.name) {
            return Err(ArbiterError::InvalidQuotaBounds {
                role: role.name.to_string(),
                reason: "duplicate role registration".to_owned(),
            });
        }
        if let Some(ref parent_name) = role.parent {
            if !self.roles.iter().any(|r| &r.name == parent_name) {
                return Err(ArbiterError::RoleNotFound {
                    role: parent_name.to_string(),
                });
            }
        }
        self.roles.push(role);
        Ok(())
    }

    /// Looks up a [`Role`] by name.
    ///
    /// # Arguments
    ///
    /// * `name` - Target [`RoleName`].
    ///
    /// # Returns
    ///
    /// Reference to the [`Role`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::RoleNotFound`] if no such role is registered.
    pub fn get_role(&self, name: &RoleName) -> ArbiterResult<&Role> {
        self.roles
            .iter()
            .find(|r| &r.name == name)
            .ok_or_else(|| ArbiterError::RoleNotFound {
                role: name.to_string(),
            })
    }

    /// Returns the slice of all registered roles.
    ///
    /// # Returns
    ///
    /// Slice `&[Role]`.
    pub fn roles(&self) -> &[Role] {
        &self.roles
    }
}

/// Workload scheduling priority tier (`SystemCritical` down to `Revocable`).
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub enum PriorityClass {
    /// Borrowed idle capacity that can be reclaimed immediately when the quota owner needs it.
    Revocable,
    /// Opportunistic spot workload subject to preemption.
    SpotPreemptible,
    /// Standard asynchronous batch or training job.
    Batch,
    /// Default online production service tier.
    ProductionStandard,
    /// High-priority latency-sensitive production tier (e.g., primary databases, inference).
    ProductionHigh,
    /// Cluster-critical system daemon tier (never preempted by user workloads).
    SystemCritical,
}

/// Action taken when a running task is selected for preemption/eviction.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub enum PreemptionPolicy {
    /// Trigger checkpoint hook (`SIGUSR1` / runtime checkpoint) and suspend before reclamation.
    CheckpointAndSuspend,
    /// Send graceful termination signal (`SIGTERM`) with grace period before `SIGKILL`.
    GracefulSigterm,
    /// Terminate immediately (`SIGKILL` / `TerminateJobObject` / `jail_remove`).
    ImmediateKill,
    /// Protected from automated preemption.
    NonPreemptible,
}

/// Hardware topology placement constraint for a task or task group.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub enum TopologyConstraint {
    /// CPU cores, RAM, and accelerators must reside on the same NUMA domain.
    SameNuma,
    /// Allocated GPUs and RDMA NICs must share a common `PCIe` switch (`GPUDirect RDMA`).
    SamePcieSwitch,
    /// Multi-GPU allocation must be interconnected via `NVLink` / `NVSwitch` or Infinity Fabric.
    NvLinkConnected,
    /// Multi-host TPU Pod allocation must form a healthy contiguous 2D/3D ICI torus.
    TpuTorusContiguous(TpuTopologySlice),
    /// Tasks within the group must be placed on distinct physical Agent hosts.
    AntiAffinityHost,
}

/// Content-addressable artifact download and extraction specification.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct ArtifactSpec {
    /// Source URI (`https://`, `s3://`, `oci://`, or `arbiter-p2p://`).
    pub uri: String,
    /// Expected hex-encoded SHA-256 digest of the artifact payload.
    pub sha256_hex: String,
    /// Whether to extract archive (`tar.gz` / `tar.zst` / `zip`) into the task sandbox.
    pub extract: bool,
    /// Whether to mark the fetched binary as executable (`chmod +x`).
    pub executable: bool,
}

/// Encrypted secret injection specification for a task sandbox.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct SecretMountSpec {
    /// Identifier of the secret in the control plane.
    pub secret_id: SecretId,
    /// Target in-memory `tmpfs` / `ramdisk` relative path inside the sandbox.
    pub mount_path: String,
}

/// Protocol used for active task readiness and liveness probing.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub enum HealthCheckProtocol {
    /// TCP socket connect check on the specified port.
    Tcp,
    /// HTTP `GET` check expecting a `200..299` status on the given request path (e.g., `"/healthz"`).
    HttpGet(String),
    /// QUIC / gRPC health probe on the specified port.
    QuicPing,
}

/// Active health probe configuration for a running task.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct HealthCheckSpec {
    /// Probe protocol.
    pub protocol: HealthCheckProtocol,
    /// Target port number.
    pub port: PortNumber,
    /// Probe interval in milliseconds.
    pub interval_ms: u64,
    /// Probe timeout in milliseconds.
    pub timeout_ms: u64,
    /// Number of consecutive failures before transitioning task to `Failed`.
    pub unhealthy_threshold: u32,
}

/// Isolation and runtime configuration for a task.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct IsolationSpec {
    /// Required OS/runtime isolation engines.
    pub capabilities: Vec<IsolationCapability>,
    /// Optional OCI container image reference or `MicroVM` rootfs image.
    pub image_ref: Option<String>,
    /// Command executable path or entrypoint.
    pub command: String,
    /// Command-line arguments.
    pub args: Vec<String>,
    /// Environment variables (`KEY=VALUE`).
    pub env: Vec<(String, String)>,
    /// Optional OS username to run the process under.
    pub run_as_user: Option<String>,
}

/// Specification for an individual schedulable task.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct TaskSpec {
    /// Unique task identifier.
    pub task_id: TaskId,
    /// Scheduling role charging this task's resources.
    pub role: RoleName,
    /// Optional framework ID (`None` for direct jobs submitted via `ArbiterClient`).
    pub framework_id: Option<FrameworkId>,
    /// Optional `CaaS` stateful election group participation (e.g., Postgres/`MySQL`/etcd cluster ID).
    pub election_group: Option<ElectionGroupId>,
    /// Scheduling priority class.
    pub priority: PriorityClass,
    /// Eviction/preemption handling policy.
    pub preemption_policy: PreemptionPolicy,
    /// Quantitative resource requirements.
    pub resources: ResourceBundle,
    /// Optional GPU vendor filter.
    pub required_gpu_vendor: Option<GpuVendor>,
    /// Optional GPU partitioning mode requirement.
    pub required_gpu_partition: Option<GpuPartition>,
    /// Hardware topology placement constraints.
    pub topology_constraints: Vec<TopologyConstraint>,
    /// Isolation and runtime execution specification.
    pub isolation: IsolationSpec,
    /// Content-addressable artifacts to fetch prior to task launch.
    pub artifacts: Vec<ArtifactSpec>,
    /// Secrets to unseal and inject into task `tmpfs`.
    pub secrets: Vec<SecretMountSpec>,
    /// Optional active health probe specification.
    pub health_check: Option<HealthCheckSpec>,
}

/// Specification for an atomic all-or-nothing gang-scheduled workload (`TaskGroup`).
///
/// Used for distributed GPU training (`NCCL`/`RCCL`), multi-host Google Cloud TPU Pod slices,
/// and MPI jobs.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct TaskGroupSpec {
    /// Unique gang task group identifier.
    pub group_id: TaskGroupId,
    /// Role owning the gang job.
    pub role: RoleName,
    /// Member tasks that must be placed and launched atomically.
    pub tasks: Vec<TaskSpec>,
    /// Optional Pod-level TPU topology slice constraint across hosts.
    pub tpu_slice: Option<TpuTopologySlice>,
    /// Maximum reservation wait time in milliseconds before rolling back partial reservations.
    pub placement_timeout_ms: u64,
}

/// Lifecycle state of a task managed by Arbiter.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub enum TaskState {
    /// Queued in the scheduler awaiting placement.
    Pending,
    /// Bound to an Agent; isolator pipeline is preparing sandboxes/datasets.
    Staging,
    /// Agent is downloading and verifying content-addressable artifacts.
    FetchingArtifacts,
    /// Executor is spawning the isolated process/container/`MicroVM`.
    Starting,
    /// Task process is active and passing readiness/liveness probes.
    Running,
    /// Task is writing a state checkpoint prior to suspension or migration.
    Checkpointing,
    /// Task is being preempted to free capacity for a higher-priority workload.
    Preempting,
    /// Task is being explicitly terminated by user or framework request.
    Killing,
    /// Terminal state: task exited cleanly with exit code `0`.
    Finished,
    /// Terminal state: task crashed, failed health checks, or isolator failed.
    Failed,
    /// Terminal state: task was terminated via preemption, fencing, or kill command.
    Killed,
    /// Terminal state: hosting Agent lost contact beyond lease TTL and was fenced.
    Lost,
}

impl TaskState {
    /// Returns the canonical string name of this [`TaskState`].
    ///
    /// # Returns
    ///
    /// Static state name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "Pending",
            Self::Staging => "Staging",
            Self::FetchingArtifacts => "FetchingArtifacts",
            Self::Starting => "Starting",
            Self::Running => "Running",
            Self::Checkpointing => "Checkpointing",
            Self::Preempting => "Preempting",
            Self::Killing => "Killing",
            Self::Finished => "Finished",
            Self::Failed => "Failed",
            Self::Killed => "Killed",
            Self::Lost => "Lost",
        }
    }

    /// Returns `true` if this state is a terminal lifecycle state (`Finished`, `Failed`, `Killed`, `Lost`).
    ///
    /// # Returns
    ///
    /// `true` if terminal.
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Finished | Self::Failed | Self::Killed | Self::Lost
        )
    }

    /// Validates whether transitioning from `self` to `next` is permitted by the task state machine.
    ///
    /// # Arguments
    ///
    /// * `next` - Target [`TaskState`].
    ///
    /// # Returns
    ///
    /// `Ok(())` if the transition is valid.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::TaskStateTransitionInvalid`] if the transition is forbidden
    /// (e.g., transitioning out of a terminal state or skipping required staging phases).
    pub fn validate_transition(self, next: Self) -> ArbiterResult<()> {
        if self.is_terminal() {
            return Err(ArbiterError::TaskStateTransitionInvalid {
                from_state: self.as_str().to_owned(),
                to_state: next.as_str().to_owned(),
            });
        }
        // Any non-terminal state can transition to Failed, Killed, Lost, or Killing
        if matches!(
            next,
            Self::Failed | Self::Killed | Self::Lost | Self::Killing
        ) {
            return Ok(());
        }
        let valid = matches!(
            (self, next),
            (Self::Pending, Self::Staging)
                | (Self::Staging, Self::FetchingArtifacts | Self::Starting)
                | (Self::FetchingArtifacts, Self::Starting)
                | (Self::Starting, Self::Running)
                | (
                    Self::Running,
                    Self::Checkpointing | Self::Preempting | Self::Finished
                )
                | (
                    Self::Checkpointing,
                    Self::Preempting | Self::Running | Self::Finished
                )
        );
        if !valid {
            return Err(ArbiterError::TaskStateTransitionInvalid {
                from_state: self.as_str().to_owned(),
                to_state: next.as_str().to_owned(),
            });
        }
        Ok(())
    }
}

impl fmt::Display for TaskState {
    /// Formats the task state name.
    ///
    /// # Arguments
    ///
    /// * `f` - The formatter.
    ///
    /// # Returns
    ///
    /// `fmt::Result`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Filter parameters attached by a Framework when declining or suppressing offers.
#[derive(
    Debug,
    Default,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct OfferFilter {
    /// Duration in milliseconds to refuse offers from the same Agent (`0` = default 5s).
    pub refuse_milliseconds: u64,
    /// Minimum CPU millicores required before sending another offer.
    pub min_cpu_millicores: u64,
    /// Minimum memory bytes required before sending another offer.
    pub min_memory_bytes: Bytes,
}

/// Mesos-inspired resource offer leased to a registered Framework.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct ResourceOffer {
    /// Unique offer identifier.
    pub offer_id: OfferId,
    /// Target framework receiving the offer.
    pub framework_id: FrameworkId,
    /// Agent hosting the offered resources.
    pub agent_id: AgentId,
    /// Role under which the resources are offered.
    pub role: RoleName,
    /// Offered resource capacity.
    pub resources: ResourceBundle,
    /// Whether these resources are borrowed revocable capacity.
    pub revocable: bool,
    /// Monotonic tick at which this offer expires if not accepted.
    pub expires_at_tick: u64,
}

/// Persistent volume creation payload inside an [`OfferOperation`].
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct VolumeReservationSpec {
    /// Volume identifier.
    pub volume_id: VolumeId,
    /// Capacity in bytes.
    pub capacity: Bytes,
    /// Sandbox mount path.
    pub container_path: String,
}

/// Operations a Framework can perform on one or more [`ResourceOffer`]s.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub enum OfferOperation {
    /// Launch a single task consuming part or all of the offered bundle.
    LaunchTask(Box<TaskSpec>),
    /// Launch an atomic task group on the offered bundle.
    LaunchTaskGroup(TaskGroupSpec),
    /// Dynamically reserve resources for the framework's role.
    Reserve(ResourceBundle),
    /// Unreserve previously dynamically reserved resources.
    Unreserve(ResourceBundle),
    /// Create a persistent local or ZFS volume.
    CreateVolume(VolumeReservationSpec),
    /// Destroy a persistent volume.
    DestroyVolume(VolumeId),
    /// Decline the offer with an optional suppression filter.
    Decline(OfferFilter),
}

/// Executor registration descriptor on an Agent.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct ExecutorInfo {
    /// Unique executor identifier.
    pub executor_id: ExecutorId,
    /// Hosting agent identifier.
    pub agent_id: AgentId,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::units::Millicores;

    #[test]
    fn test_quota_and_role_hierarchy() {
        let qid = QuotaId(String::from("q-prod"));
        let r_prod = RoleName(String::from("prod"));
        let r_ml = RoleName(String::from("prod.ml"));
        let r_missing = RoleName(String::from("nonexistent"));

        let mut min_b = ResourceBundle::zero();
        min_b.cpu = Millicores::new(4000);

        let mut max_b = ResourceBundle::zero();
        max_b.cpu = Millicores::new(2000);

        // Invalid: min > max
        assert!(
            Quota::new(
                qid.clone(),
                &r_prod,
                min_b.clone(),
                max_b,
                true,
                WeightBasisPoints::STANDARD,
            )
            .is_err()
        );

        let mut valid_max = ResourceBundle::zero();
        valid_max.cpu = Millicores::new(8000);

        let quota = Quota::new(
            qid,
            &r_prod,
            min_b,
            valid_max,
            true,
            WeightBasisPoints::STANDARD,
        );
        assert!(quota.is_ok());
        let quota_val = Quota {
            id: QuotaId(String::from("q-prod")),
            guaranteed_min: ResourceBundle::zero(),
            hard_max: ResourceBundle::zero(),
            allow_burst_borrowing: true,
            weight: WeightBasisPoints::STANDARD,
        };

        let mut hierarchy = RoleHierarchy::new();
        assert!(hierarchy.roles().is_empty());

        // Child role before parent role exists -> RoleNotFound
        assert!(
            hierarchy
                .add_role(Role {
                    name: r_ml.clone(),
                    parent: Some(r_prod.clone()),
                    quota: quota_val.clone(),
                })
                .is_err()
        );

        // Add parent role
        assert!(
            hierarchy
                .add_role(Role {
                    name: r_prod.clone(),
                    parent: None,
                    quota: quota_val.clone(),
                })
                .is_ok()
        );

        // Duplicate role registration -> error
        assert!(
            hierarchy
                .add_role(Role {
                    name: r_prod.clone(),
                    parent: None,
                    quota: quota_val.clone(),
                })
                .is_err()
        );

        // Add child role with valid parent
        assert!(
            hierarchy
                .add_role(Role {
                    name: r_ml.clone(),
                    parent: Some(r_prod.clone()),
                    quota: quota_val,
                })
                .is_ok()
        );

        assert_eq!(hierarchy.roles().len(), 2);
        assert!(hierarchy.get_role(&r_prod).is_ok());
        assert!(hierarchy.get_role(&r_ml).is_ok());
        assert!(hierarchy.get_role(&r_missing).is_err());
    }

    #[test]
    fn test_task_state_machine_valid_transitions() {
        let all_states = [
            TaskState::Pending,
            TaskState::Staging,
            TaskState::FetchingArtifacts,
            TaskState::Starting,
            TaskState::Running,
            TaskState::Checkpointing,
            TaskState::Preempting,
            TaskState::Killing,
            TaskState::Finished,
            TaskState::Failed,
            TaskState::Killed,
            TaskState::Lost,
        ];

        for st in all_states {
            assert!(!st.as_str().is_empty());
            assert_eq!(st.to_string(), st.as_str());
        }

        assert!(
            TaskState::Pending
                .validate_transition(TaskState::Staging)
                .is_ok()
        );
        assert!(
            TaskState::Staging
                .validate_transition(TaskState::FetchingArtifacts)
                .is_ok()
        );
        assert!(
            TaskState::Staging
                .validate_transition(TaskState::Starting)
                .is_ok()
        );
        assert!(
            TaskState::FetchingArtifacts
                .validate_transition(TaskState::Starting)
                .is_ok()
        );
        assert!(
            TaskState::Starting
                .validate_transition(TaskState::Running)
                .is_ok()
        );
        assert!(
            TaskState::Running
                .validate_transition(TaskState::Checkpointing)
                .is_ok()
        );
        assert!(
            TaskState::Running
                .validate_transition(TaskState::Preempting)
                .is_ok()
        );
        assert!(
            TaskState::Running
                .validate_transition(TaskState::Finished)
                .is_ok()
        );
        assert!(
            TaskState::Checkpointing
                .validate_transition(TaskState::Preempting)
                .is_ok()
        );
        assert!(
            TaskState::Checkpointing
                .validate_transition(TaskState::Running)
                .is_ok()
        );
        assert!(
            TaskState::Checkpointing
                .validate_transition(TaskState::Finished)
                .is_ok()
        );
    }

    #[test]
    fn test_task_state_machine_terminal_and_invalid_transitions() {
        for non_term in [
            TaskState::Pending,
            TaskState::Staging,
            TaskState::FetchingArtifacts,
            TaskState::Starting,
            TaskState::Running,
            TaskState::Checkpointing,
            TaskState::Preempting,
            TaskState::Killing,
        ] {
            assert!(!non_term.is_terminal());
            assert!(non_term.validate_transition(TaskState::Failed).is_ok());
            assert!(non_term.validate_transition(TaskState::Killed).is_ok());
            assert!(non_term.validate_transition(TaskState::Lost).is_ok());
            assert!(non_term.validate_transition(TaskState::Killing).is_ok());
        }

        for term in [
            TaskState::Finished,
            TaskState::Failed,
            TaskState::Killed,
            TaskState::Lost,
        ] {
            assert!(term.is_terminal());
            assert!(term.validate_transition(TaskState::Running).is_err());
            assert!(term.validate_transition(TaskState::Failed).is_err());
        }

        assert!(
            TaskState::Pending
                .validate_transition(TaskState::Running)
                .is_err()
        );
        assert!(
            TaskState::Running
                .validate_transition(TaskState::Pending)
                .is_err()
        );
        assert!(
            TaskState::Preempting
                .validate_transition(TaskState::Running)
                .is_err()
        );
        assert!(
            TaskState::Killing
                .validate_transition(TaskState::Running)
                .is_err()
        );
    }
}
