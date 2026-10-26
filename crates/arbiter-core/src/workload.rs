//! Workload specifications, task state machine, hierarchical roles, quotas, and resource offers.
//!
//! Models both Mesos 2-level `ResourceOffer` / `OfferOperation` workflows and direct task /
//! gang-scheduled (`TaskGroupSpec`) workloads with strict state transition validation.

use core::fmt;
use std::collections::BTreeMap;

use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use serde::{Deserialize, Serialize};

use crate::error::{ArbiterError, ArbiterResult};
use crate::ids::{
    AgentId, ContainerId, ElectionGroupId, ExecutorId, ExitCode, FrameworkId, MaintenanceWindowId,
    OfferId, OperationId, PrincipalName, QuotaId, RegionName, ResourceProviderId, RoleName,
    SecretId, StatusUpdateUuid, TaskGroupId, TaskId, VolumeId, ZoneName,
};
use crate::platform::IsolationCapability;
use crate::resources::{
    CpuResource, GpuPartition, GpuVendor, MemoryResource, NetworkResource, ResourceBundle,
    StorageResource, TpuTopologySlice,
};
use crate::units::{
    BenchmarkTicks, Bytes, FailoverTimeoutMillis, PortNumber, WallClockUnixMillis,
    WeightBasisPoints,
};

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
    /// If `role.parent` is `Some`, the parent role must already be registered, and the sum of
    /// all child roles' `guaranteed_min` and `hard_max` under that parent must not exceed the
    /// parent role's `guaranteed_min` and `hard_max`.
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
    /// [`ArbiterError::InvalidQuotaBounds`] if a role with the same name already exists or if the
    /// child quota exceeds its parent role's quota ceiling.
    pub fn add_role(&mut self, role: Role) -> ArbiterResult<()> {
        if self.roles.iter().any(|r| r.name == role.name) {
            return Err(ArbiterError::InvalidQuotaBounds {
                role: role.name.to_string(),
                reason: "duplicate role registration".to_owned(),
            });
        }
        if let Some(ref parent_name) = role.parent {
            let Some(parent_role) = self.roles.iter().find(|r| &r.name == parent_name) else {
                return Err(ArbiterError::RoleNotFound {
                    role: parent_name.to_string(),
                });
            };
            let mut children_min = role.quota.guaranteed_min.clone();
            let mut children_max = role.quota.hard_max.clone();
            for sibling in self
                .roles
                .iter()
                .filter(|r| r.parent.as_ref() == Some(parent_name))
            {
                children_min = children_min
                    .try_add(&sibling.quota.guaranteed_min)
                    .unwrap_or_default();
                children_max = children_max
                    .try_add(&sibling.quota.hard_max)
                    .unwrap_or_default();
            }
            if (!parent_role.quota.guaranteed_min.is_empty()
                && !parent_role.quota.guaranteed_min.contains(&children_min))
                || !parent_role.quota.hard_max.contains(&children_max)
            {
                return Err(ArbiterError::InvalidQuotaBounds {
                    role: role.name.to_string(),
                    reason: format!(
                        "aggregate child role quota exceeds parent role '{parent_name}' quota bounds"
                    ),
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

    /// Updates or sets the [`Quota`] for an existing role, or registers a new top-level role with `quota`.
    ///
    /// # Arguments
    ///
    /// * `role_name` - Target [`RoleName`].
    /// * `quota` - Validated [`Quota`] policy to apply.
    ///
    /// # Returns
    ///
    /// `Ok(())` on update or registration.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::InvalidQuotaBounds`] if `quota.hard_max` does not contain `quota.guaranteed_min`.
    pub fn set_role_quota(&mut self, role_name: &RoleName, quota: Quota) -> ArbiterResult<()> {
        if !quota.hard_max.contains(&quota.guaranteed_min) {
            return Err(ArbiterError::InvalidQuotaBounds {
                role: role_name.to_string(),
                reason: "hard_max bundle must be >= guaranteed_min on all resource dimensions"
                    .to_owned(),
            });
        }
        if let Some(existing) = self.roles.iter_mut().find(|r| &r.name == role_name) {
            existing.quota = quota;
            return Ok(());
        }
        self.roles.push(Role {
            name: role_name.clone(),
            parent: None,
            quota,
        });
        Ok(())
    }

    /// Resets a role's quota to unbounded `hard_max` (`ResourceBundle::max_bound_for_default()`) and zero `guaranteed_min`.
    ///
    /// # Arguments
    ///
    /// * `role_name` - Target [`RoleName`] whose quota is being removed.
    ///
    /// # Returns
    ///
    /// `Ok(())` when the quota is cleared.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::RoleNotFound`] if `role_name` is not registered.
    pub fn remove_role_quota(&mut self, role_name: &RoleName) -> ArbiterResult<()> {
        let Some(existing) = self.roles.iter_mut().find(|r| &r.name == role_name) else {
            return Err(ArbiterError::RoleNotFound {
                role: role_name.to_string(),
            });
        };
        existing.quota.guaranteed_min = ResourceBundle::zero();
        Ok(())
    }

    /// Updates the HDRF fairness [`WeightBasisPoints`] for a registered role.
    ///
    /// # Arguments
    ///
    /// * `role_name` - Target [`RoleName`].
    /// * `weight` - New [`WeightBasisPoints`] (`> 0`).
    ///
    /// # Returns
    ///
    /// `Ok(())` when the weight is updated.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::RoleNotFound`] if `role_name` is not registered.
    pub fn update_role_weight(
        &mut self,
        role_name: &RoleName,
        weight: WeightBasisPoints,
    ) -> ArbiterResult<()> {
        let Some(existing) = self.roles.iter_mut().find(|r| &r.name == role_name) else {
            return Err(ArbiterError::RoleNotFound {
                role: role_name.to_string(),
            });
        };
        existing.quota.weight = weight;
        Ok(())
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
    /// Strongly-typed microarchitectural, NUMA hugepage/unified memory, storage I/O, network fabric,
    /// attribute, fault-domain, shared volume, kill policy, and custom executor requirements.
    ExtendedRequirements(Box<TaskSchedulingRequirements>),
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

/// Declarative task-level microarchitectural, NUMA memory pool, storage I/O, network fabric,
/// fault-domain, attribute, shared volume, kill policy, and custom executor requirements.
#[derive(
    Debug,
    Default,
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
pub struct TaskSchedulingRequirements {
    /// Optional CPU microarchitecture requirement (`preferred_core_class`, `required_extensions`).
    pub cpu_resource: Option<CpuResource>,
    /// Optional NUMA memory pool requirement (`hugepages_2mib_bytes`, `hugepages_1gib_bytes`, `require_unified_memory`).
    pub memory_resource: Option<MemoryResource>,
    /// Optional storage IOPS, throughput, and media class requirement (`max_iops`, `throughput_bps`, `disk_class`).
    #[serde(default)]
    pub storage_resource: Option<StorageResource>,
    /// Optional network ingress/egress bandwidth and SR-IOV RDMA VF requirement (`ingress_bps`, `egress_bps`, `rdma_vfs`).
    #[serde(default)]
    pub network_resource: Option<NetworkResource>,
    /// Declarative attribute & spread constraints (`Equals`, `NotEquals`, `InSet`, `MaxPerHostname`, `MaxPerFaultDomain`).
    #[serde(default)]
    pub placement_constraints: Vec<PlacementConstraint>,
    /// Optional required fault domain (`RegionName` + `ZoneName`).
    #[serde(default)]
    pub required_domain: Option<DomainInfo>,
    /// Shared or exclusive persistent volume mounts (`(VolumeId, SharedVolumeMode)`).
    #[serde(default)]
    pub shared_volume_mounts: Vec<(VolumeId, SharedVolumeMode)>,
    /// Graceful termination policy (`grace_period_ticks` between `SIGTERM` and `SIGKILL`).
    #[serde(default)]
    pub kill_policy: KillPolicy,
    /// Optional custom Mesos executor descriptor (`None` uses the built-in command or task-group executor).
    #[serde(default)]
    pub executor_info: Option<ExecutorInfo>,
}

/// Environment variable key retained only for backwards-compatible deserialization of legacy task manifests.
pub const ARBITER_SCHEDULING_REQUIREMENTS_ENV_KEY: &str = "ARBITER_SCHEDULING_REQUIREMENTS";

impl TaskSchedulingRequirements {
    /// Attaches this [`TaskSchedulingRequirements`] as a strongly-typed
    /// [`TopologyConstraint::ExtendedRequirements`] entry on `task.topology_constraints`,
    /// replacing any previous entry and removing any legacy `ARBITER_SCHEDULING_REQUIREMENTS` env var.
    ///
    /// # Arguments
    ///
    /// * `task` - Mutable [`TaskSpec`] to update.
    pub fn attach_to_task(&self, task: &mut TaskSpec) {
        task.isolation
            .env
            .retain(|(k, _)| k != ARBITER_SCHEDULING_REQUIREMENTS_ENV_KEY);
        task.topology_constraints
            .retain(|c| !matches!(c, TopologyConstraint::ExtendedRequirements(_)));
        task.topology_constraints
            .push(TopologyConstraint::ExtendedRequirements(Box::new(
                self.clone(),
            )));
    }

    /// Extracts [`TaskSchedulingRequirements`] from `task.topology_constraints` (or falls back
    /// to legacy `task.isolation.env` if not present in `topology_constraints`).
    ///
    /// # Arguments
    ///
    /// * `task` - [`TaskSpec`] to inspect.
    ///
    /// # Returns
    ///
    /// `Some(TaskSchedulingRequirements)` if present, or `None`.
    pub fn from_task(task: &TaskSpec) -> Option<Self> {
        for constraint in &task.topology_constraints {
            if let TopologyConstraint::ExtendedRequirements(reqs) = constraint {
                return Some((**reqs).clone());
            }
        }
        task.isolation
            .env
            .iter()
            .find(|(k, _)| k == ARBITER_SCHEDULING_REQUIREMENTS_ENV_KEY)
            .and_then(|(_, v)| serde_json::from_str(v).ok())
    }
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

impl TaskSpec {
    /// Returns a builder-style copy of `self` with `requirements` attached as a strongly-typed
    /// [`TopologyConstraint::ExtendedRequirements`] entry.
    ///
    /// # Arguments
    ///
    /// * `requirements` - [`TaskSchedulingRequirements`] to attach.
    ///
    /// # Returns
    ///
    /// Updated [`TaskSpec`].
    #[must_use]
    pub fn with_scheduling_requirements(
        mut self,
        requirements: &TaskSchedulingRequirements,
    ) -> Self {
        requirements.attach_to_task(&mut self);
        self
    }

    /// Returns the effective [`TaskSchedulingRequirements`] for this task (or `Default::default()`).
    ///
    /// # Returns
    ///
    /// [`TaskSchedulingRequirements`] configured on this task.
    pub fn scheduling_requirements(&self) -> TaskSchedulingRequirements {
        TaskSchedulingRequirements::from_task(self).unwrap_or_default()
    }

    /// Returns the strongly-typed [`CpuResource`] requirements for this task.
    ///
    /// # Returns
    ///
    /// [`CpuResource`] combining `self.resources.cpu` and any microarchitectural preferences.
    pub fn cpu_requirements(&self) -> CpuResource {
        let mut cpu = self
            .scheduling_requirements()
            .cpu_resource
            .unwrap_or_default();
        if cpu.millicores.is_zero() {
            cpu.millicores = self.resources.cpu;
        }
        cpu
    }

    /// Returns the strongly-typed [`MemoryResource`] requirements for this task.
    ///
    /// # Returns
    ///
    /// [`MemoryResource`] combining `self.resources.memory` and any `HugePage` / unified memory settings.
    pub fn memory_requirements(&self) -> MemoryResource {
        let mut mem = self
            .scheduling_requirements()
            .memory_resource
            .unwrap_or_default();
        if mem.ram_bytes.is_zero() {
            mem.ram_bytes = self.resources.memory;
        }
        mem
    }

    /// Returns the strongly-typed [`StorageResource`] requirements for this task.
    ///
    /// # Returns
    ///
    /// [`StorageResource`] combining `self.resources.disk` and any IOPS/throughput/class constraints.
    pub fn storage_requirements(&self) -> StorageResource {
        let mut storage = self
            .scheduling_requirements()
            .storage_resource
            .unwrap_or_default();
        if storage.capacity_bytes.is_zero() {
            storage.capacity_bytes = self.resources.disk;
        }
        storage
    }

    /// Returns the strongly-typed [`NetworkResource`] requirements for this task.
    ///
    /// # Returns
    ///
    /// [`NetworkResource`] combining `self.resources.network_bandwidth` / `ports` and RDMA VF counts.
    pub fn network_requirements(&self) -> NetworkResource {
        let mut net = self
            .scheduling_requirements()
            .network_resource
            .unwrap_or_default();
        if net.ingress_bps.is_zero() {
            net.ingress_bps = self.resources.network_bandwidth;
        }
        if net.ports.total_ports() == 0 {
            net.ports = self.resources.ports.clone();
        }
        net
    }

    /// Returns the declarative [`PlacementConstraint`]s attached to this task.
    ///
    /// # Returns
    ///
    /// Vector of [`PlacementConstraint`]s.
    pub fn placement_constraints(&self) -> Vec<PlacementConstraint> {
        self.scheduling_requirements().placement_constraints
    }

    /// Returns the preferred or required [`DomainInfo`] fault domain for this task.
    ///
    /// # Returns
    ///
    /// `Option<DomainInfo>`.
    pub fn fault_domain_preference(&self) -> Option<DomainInfo> {
        self.scheduling_requirements().required_domain
    }

    /// Returns the persistent volume mounts and [`SharedVolumeMode`]s requested by this task.
    ///
    /// # Returns
    ///
    /// Vector of `(VolumeId, SharedVolumeMode)` pairs.
    pub fn shared_volume_mounts(&self) -> Vec<(VolumeId, SharedVolumeMode)> {
        self.scheduling_requirements().shared_volume_mounts
    }

    /// Returns the [`KillPolicy`] configured for this task.
    ///
    /// # Returns
    ///
    /// [`KillPolicy`].
    pub fn kill_policy(&self) -> KillPolicy {
        self.scheduling_requirements().kill_policy
    }

    /// Returns the optional custom [`ExecutorInfo`] configured for this task.
    ///
    /// # Returns
    ///
    /// `Option<ExecutorInfo>`.
    pub fn executor_info(&self) -> Option<ExecutorInfo> {
        self.scheduling_requirements().executor_info
    }
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
    /// Task is hosted on a transiently partitioned Agent awaiting re-registration (Mesos `TASK_UNREACHABLE`).
    Unreachable,
    /// Terminal state: task exited cleanly with exit code `0`.
    Finished,
    /// Terminal state: task crashed, failed health checks, or isolator failed.
    Failed,
    /// Terminal state: task was terminated via preemption, fencing, or kill command.
    Killed,
    /// Terminal state: task specification contained malformed parameters (`TASK_ERROR`).
    Error,
    /// Terminal state: task launch or status message was dropped in transit during a partition (`TASK_DROPPED`).
    Dropped,
    /// Terminal state: hosting Agent lost contact beyond lease TTL and was fenced.
    Lost,
    /// Terminal state: hosting Agent was permanently decommissioned during a partition (`TASK_GONE`).
    Gone,
    /// Terminal state: operator explicitly marked the hosting Agent gone (`TASK_GONE_BY_OPERATOR`).
    GoneByOperator,
    /// Terminal reconciliation state: Master has no record of the queried task (`TASK_UNKNOWN`).
    Unknown,
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
            Self::Unreachable => "Unreachable",
            Self::Finished => "Finished",
            Self::Failed => "Failed",
            Self::Killed => "Killed",
            Self::Error => "Error",
            Self::Dropped => "Dropped",
            Self::Lost => "Lost",
            Self::Gone => "Gone",
            Self::GoneByOperator => "GoneByOperator",
            Self::Unknown => "Unknown",
        }
    }

    /// Returns `true` if this state is a terminal lifecycle state (`Finished`, `Failed`, `Killed`, `Error`, `Dropped`, `Lost`, `Gone`, `GoneByOperator`, `Unknown`).
    ///
    /// # Returns
    ///
    /// `true` if terminal.
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Finished
                | Self::Failed
                | Self::Killed
                | Self::Error
                | Self::Dropped
                | Self::Lost
                | Self::Gone
                | Self::GoneByOperator
                | Self::Unknown
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
        // Any non-terminal state can transition to Failed, Killed, Error, Dropped, Lost, Killing, Unreachable, Gone, or GoneByOperator
        if matches!(
            next,
            Self::Failed
                | Self::Killed
                | Self::Error
                | Self::Dropped
                | Self::Lost
                | Self::Killing
                | Self::Unreachable
                | Self::Gone
                | Self::GoneByOperator
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
                | (Self::Unreachable, Self::Running | Self::Finished)
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
pub struct OfferFilter {
    /// Duration in milliseconds to refuse offers from the same Agent (`0` = default 5s).
    pub refuse_milliseconds: u64,
    /// Minimum CPU millicores required before sending another offer.
    pub min_cpu_millicores: u64,
    /// Minimum memory bytes required before sending another offer.
    pub min_memory_bytes: Bytes,
    /// Whether to refuse offers that contain GPU capacity (`true` = refuse GPU offers).
    #[serde(default)]
    pub refuse_gpu_offers: bool,
    /// Minimum GPU VRAM bytes required before sending a GPU offer.
    #[serde(default)]
    pub min_gpu_vram: Bytes,
}

impl OfferFilter {
    /// Default Mesos offer refusal duration in ticks when `refuse_milliseconds == 0` (`5` ticks).
    pub const DEFAULT_REFUSE_TICKS: u64 = 5;

    /// Computes the monotonic expiration tick (`created_tick + refuse_ticks`) for this [`OfferFilter`].
    ///
    /// # Arguments
    ///
    /// * `created_tick` - Tick at which the offer was accepted or declined.
    ///
    /// # Returns
    ///
    /// Monotonic tick when the suppression filter expires and resources become eligible for re-offering.
    pub const fn expiration_tick(&self, created_tick: BenchmarkTicks) -> BenchmarkTicks {
        let delta_ticks = if self.refuse_milliseconds == 0 {
            Self::DEFAULT_REFUSE_TICKS
        } else {
            let scaled = self.refuse_milliseconds / 1_000;
            if scaled == 0 { 1 } else { scaled }
        };
        created_tick.saturating_add(BenchmarkTicks::new(delta_ticks))
    }

    /// Returns `true` if `current_tick < self.expiration_tick(created_tick)`.
    ///
    /// # Arguments
    ///
    /// * `created_tick` - Tick when the filter was installed.
    /// * `current_tick` - Current cluster monotonic tick.
    ///
    /// # Returns
    ///
    /// `true` if the filter is still actively suppressing offers on the Agent.
    pub const fn is_active_at(
        &self,
        created_tick: BenchmarkTicks,
        current_tick: BenchmarkTicks,
    ) -> bool {
        current_tick.get() < self.expiration_tick(created_tick).get()
    }

    /// Evaluates whether `candidate` resources satisfy this filter's minimum CPU/memory/GPU thresholds.
    ///
    /// # Arguments
    ///
    /// * `candidate` - Allocatable [`ResourceBundle`] on the Agent.
    ///
    /// # Returns
    ///
    /// `true` if `candidate` meets all minimum thresholds and GPU preferences of this filter.
    pub const fn allows_bundle(&self, candidate: &ResourceBundle) -> bool {
        if candidate.cpu.get() < self.min_cpu_millicores {
            return false;
        }
        if candidate.memory.get() < self.min_memory_bytes.get() {
            return false;
        }
        if self.refuse_gpu_offers && candidate.gpu_compute.get() > 0 {
            return false;
        }
        if candidate.gpu_vram.get() < self.min_gpu_vram.get() {
            return false;
        }
        true
    }
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
pub struct VolumeReservationSpec {
    /// Volume identifier.
    pub volume_id: VolumeId,
    /// Capacity in bytes.
    pub capacity: Bytes,
    /// Sandbox mount path.
    pub container_path: String,
}

/// CSI / Mesos Resource Provider disk provisioning specification (`CREATE_DISK` / `DESTROY_DISK`).
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
pub struct ResourceProviderDiskSpec {
    /// Target Resource Provider identifier.
    pub provider_id: ResourceProviderId,
    /// Unique disk/volume identifier.
    pub volume_id: VolumeId,
    /// Provisioned disk source kind (`MOUNT`, `BLOCK`, `CsiVolume`, etc.).
    pub source: DiskSource,
    /// Disk capacity in bytes.
    pub capacity: Bytes,
}

/// Registration and inventory descriptor for a local or external Mesos CSI [`ResourceProviderInfo`].
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
pub struct ResourceProviderInfo {
    /// Unique Resource Provider identifier.
    pub provider_id: ResourceProviderId,
    /// Optional hosting Agent (`Some` for local CSI resource providers, `None` for external providers).
    pub agent_id: Option<AgentId>,
    /// Provider type string (e.g., `"org.apache.mesos.rp.local.storage"`).
    pub provider_type: String,
    /// Provider instance name (e.g., `"csi-zfs"`).
    pub provider_name: String,
    /// Default role under which raw storage capacity is advertised.
    pub default_role: RoleName,
    /// Advertised disk sources and their capacities in bytes.
    pub advertised_disks: Vec<(DiskSource, Bytes)>,
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
pub enum OfferOperation {
    /// Launch a single task consuming part or all of the offered bundle.
    LaunchTask(Box<TaskSpec>),
    /// Launch an atomic task group on the offered bundle.
    LaunchTaskGroup(TaskGroupSpec),
    /// Dynamically reserve resources for the framework's role.
    Reserve(ResourceBundle),
    /// Unreserve previously dynamically reserved resources.
    Unreserve(ResourceBundle),
    /// Refine an existing reservation by pushing a child role onto the reservation stack: `(child_role, resources)`.
    PushReservation(RoleName, ResourceBundle),
    /// Pop the top refined role off the reservation stack back to its parent role: `(resources)`.
    PopReservation(ResourceBundle),
    /// Create a persistent local or ZFS volume.
    CreateVolume(VolumeReservationSpec),
    /// Destroy a persistent volume.
    DestroyVolume(VolumeId),
    /// Expand an existing persistent volume by `additional_bytes` (`GROW_VOLUME`): `(volume_id, additional_bytes)`.
    GrowVolume(VolumeId, Bytes),
    /// Shrink an existing persistent volume by `subtract_bytes` (`SHRINK_VOLUME`): `(volume_id, subtract_bytes)`.
    ShrinkVolume(VolumeId, Bytes),
    /// Convert `RAW` Resource Provider storage capacity into a `MOUNT` or `BLOCK` disk (`CREATE_DISK`).
    CreateDisk(ResourceProviderDiskSpec),
    /// Reclaim a `MOUNT` or `BLOCK` Resource Provider disk back to `RAW` storage capacity (`DESTROY_DISK`).
    DestroyDisk(ResourceProviderDiskSpec),
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
pub struct ExecutorInfo {
    /// Unique executor identifier.
    pub executor_id: ExecutorId,
    /// Hosting agent identifier.
    pub agent_id: AgentId,
}

/// Whether a subscribed Framework opts into Agent-local state checkpointing across Agent restarts.
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
pub enum CheckpointMode {
    /// Agent checkpoints framework metadata, executor PIDs, and status updates to disk (default).
    #[default]
    Enabled,
    /// Agent does not checkpoint framework state across daemon restarts.
    Disabled,
}

/// Graceful termination grace period specification for `KillTask` and draining operations.
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
pub struct KillPolicy {
    /// Grace period in ticks between `SIGTERM` and `SIGKILL` escalation.
    pub grace_period_ticks: BenchmarkTicks,
}

/// Mesos v1 `InverseOffer` requesting that a Framework release resources on an Agent prior to maintenance.
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
pub struct InverseOffer {
    /// Unique identifier for this inverse offer.
    pub inverse_offer_id: OfferId,
    /// Target framework holding resources on the Agent.
    pub framework_id: FrameworkId,
    /// Agent scheduled for maintenance or draining.
    pub agent_id: AgentId,
    /// Maintenance window associated with the reclamation request.
    pub maintenance_window_id: MaintenanceWindowId,
    /// Resources requested to be vacated.
    pub resources: ResourceBundle,
    /// Tick at which unavailability begins.
    pub unavailability_start_tick: BenchmarkTicks,
}

/// Reason why a previously issued [`ResourceOffer`] was rescinded by the Master.
#[derive(
    Debug,
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
pub enum OfferRescindReason {
    /// Offer TTL elapsed before the Framework accepted or declined it.
    OfferTtlExpired,
    /// Hosting Agent lost heartbeat contact or disconnected.
    AgentDisconnected,
    /// Hosting Agent entered a maintenance window, draining mode, or deactivation.
    AgentEnteredMaintenance,
    /// Offered resources were preempted for a higher-priority / quota-guaranteed workload.
    PreemptedByHigherPriority,
    /// Operator or Framework suppressed/revoked offers for the role.
    RoleSuppressedOrRevoked,
}

/// Reason why an Agent was marked lost or removed from the cluster.
#[derive(
    Debug,
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
pub enum AgentLossReason {
    /// Heartbeat lease expired and Agent failed health reconciliation.
    HeartbeatTimeout,
    /// Operator explicitly marked the Agent gone (`MarkAgentGone`).
    MarkedGoneByOperator,
    /// Automated draining with `mark_gone` completed.
    DrainedAndDecommissioned,
}

/// Lifecycle state of a Mesos v1 Offer Operation (`RESERVE`, `UNRESERVE`, `CREATE`, `DESTROY`).
#[derive(
    Debug,
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
pub enum OperationState {
    /// Operation is queued or being applied on the Agent/ResourceProvider.
    Pending,
    /// Operation completed and resources/volumes are committed.
    Finished,
    /// Operation failed due to insufficient capacity or constraint violation.
    Failed,
    /// Operation contained malformed parameters.
    Error,
    /// Operation was dropped in transit during a partition.
    Dropped,
    /// Hosting Agent is unreachable.
    Unreachable,
    /// Hosting Agent was marked gone by an operator.
    GoneByOperator,
    /// Master has no record of the queried operation ID.
    Unknown,
}

/// Dynamic reservation metadata attached to an Agent's reserved capacity pool.
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
pub struct DynamicReservationSpec {
    /// Operation identifier for tracking and reconciliation.
    pub operation_id: OperationId,
    /// Target Agent hosting the reservation.
    pub agent_id: AgentId,
    /// Role to which the resources are dynamically reserved.
    pub role: RoleName,
    /// Authenticated principal creating the reservation.
    pub principal: String,
    /// Reserved resource bundle.
    pub resources: ResourceBundle,
}

/// Scheduled maintenance unavailability window for a set of Agents.
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
pub struct MaintenanceWindow {
    /// Unique maintenance window identifier.
    pub window_id: MaintenanceWindowId,
    /// Agents affected by this maintenance window.
    pub agent_ids: Vec<AgentId>,
    /// Monotonic tick when maintenance unavailability begins.
    pub unavailability_start_tick: BenchmarkTicks,
    /// Duration of the maintenance window in ticks.
    pub duration_ticks: BenchmarkTicks,
}

/// Cluster-wide maintenance schedule containing ordered [`MaintenanceWindow`]s.
#[derive(
    Debug,
    Default,
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
pub struct MaintenanceSchedule {
    /// Scheduled maintenance windows.
    pub windows: Vec<MaintenanceWindow>,
}

/// Behavior when an Agent finishes draining all running tasks.
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
pub enum DrainCompletionMode {
    /// Transition the Agent to `Drained` so it can be reactivated later (default).
    #[default]
    RemainDrained,
    /// Automatically mark the Agent gone (`TASK_GONE_BY_OPERATOR`) and decommission it upon drain completion.
    MarkGoneOnComplete,
}

/// Framework decision in response to an [`InverseOffer`] for upcoming Agent maintenance (`RespondInverseOffer`).
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
pub enum InverseOfferResponse {
    /// Framework accepts the maintenance window and agrees to release or migrate affected resources (default).
    #[default]
    AcceptMaintenance,
    /// Framework declines the inverse offer, indicating it cannot safely vacate the resources yet.
    DeclineMaintenance,
}

impl InverseOfferResponse {
    /// Returns `true` if the framework accepted the maintenance window (`AcceptMaintenance`).
    ///
    /// # Returns
    ///
    /// `true` when `Self::AcceptMaintenance`.
    pub const fn is_accepted(self) -> bool {
        matches!(self, Self::AcceptMaintenance)
    }

    /// Converts a boolean acceptance flag into an [`InverseOfferResponse`].
    ///
    /// # Arguments
    ///
    /// * `accepted` - `true` for [`Self::AcceptMaintenance`], `false` for [`Self::DeclineMaintenance`].
    ///
    /// # Returns
    ///
    /// Corresponding [`InverseOfferResponse`].
    pub const fn from_bool(accepted: bool) -> Self {
        if accepted {
            Self::AcceptMaintenance
        } else {
            Self::DeclineMaintenance
        }
    }
}

/// Payload for [`AgentMaintenanceState::Draining`].
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
pub struct DrainingSpec {
    /// Post-drain completion behavior.
    pub completion_mode: DrainCompletionMode,
    /// Maximum grace period in ticks for task eviction.
    pub grace_period_ticks: BenchmarkTicks,
}

/// Per-Agent maintenance and draining state machine (Mesos Maintenance & Draining parity).
#[derive(
    Debug,
    Default,
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
pub enum AgentMaintenanceState {
    /// Agent is operating normally and eligible for scheduling and offers.
    #[default]
    Normal,
    /// Agent is scheduled for an upcoming maintenance window (`InverseOffer`s sent).
    ScheduledForMaintenance(MaintenanceWindowId),
    /// Agent is actively draining tasks (`KillTask` sent, new offers blocked).
    Draining(DrainingSpec),
    /// All tasks on the Agent have reached terminal states; Agent is safely drained.
    Drained,
    /// Agent is in active maintenance (`Down` machine mode) or operator-deactivated.
    Deactivated,
}

/// Resource request hint sent by a Framework via `RequestResources`.
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
pub struct ResourceRequest {
    /// Optional preferred Agent (`None` = any Agent in cluster or federation).
    pub agent_id: Option<AgentId>,
    /// Desired resource bundle.
    pub resources: ResourceBundle,
}

/// Master leader metadata returned to subscribed Frameworks and Operators.
#[derive(
    Debug,
    Default,
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
pub struct MasterInfo {
    /// Leader node identifier.
    pub leader_id: String,
    /// Cluster version string.
    pub version: String,
    /// Current monotonic leader term/epoch.
    pub elected_term: u64,
}

/// Fault-domain coordinates (`Region` + `Zone`) for rack/zone/region-aware scheduling (Mesos `DomainInfo::FaultDomain`).
#[derive(
    Debug,
    Default,
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
pub struct FaultDomain {
    /// Geographic region identifier (e.g., `"us-east-1"`).
    pub region: RegionName,
    /// Availability zone or rack identifier (e.g., `"us-east-1a:rack-04"`).
    pub zone: ZoneName,
}

/// Fault domain descriptor attached to a `MasterInfo`, `RegisterAgent`, or `ResourceOffer` (Mesos `DomainInfo`).
#[derive(
    Debug,
    Default,
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
pub struct DomainInfo {
    /// Fault domain coordinates (`region` and `zone`).
    pub fault_domain: FaultDomain,
}

impl DomainInfo {
    /// Creates a new [`DomainInfo`] from `region` and `zone`.
    ///
    /// # Arguments
    ///
    /// * `region` - [`RegionName`].
    /// * `zone` - [`ZoneName`].
    ///
    /// # Returns
    ///
    /// Initialized [`DomainInfo`].
    pub const fn new(region: RegionName, zone: ZoneName) -> Self {
        Self {
            fault_domain: FaultDomain { region, zone },
        }
    }

    /// Returns `true` if `other` is in a different geographic region (Mesos `REMOTE` region check).
    ///
    /// # Arguments
    ///
    /// * `other` - Peer [`DomainInfo`] to compare against.
    ///
    /// # Returns
    ///
    /// `true` if `self.fault_domain.region != other.fault_domain.region`.
    pub fn is_remote_region(&self, other: &Self) -> bool {
        self.fault_domain.region != other.fault_domain.region
    }
}

/// Typed value of an [`AgentAttribute`] (Mesos `Attribute` value types: `TEXT`, `SCALAR`, `RANGES`, `SET`).
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
pub enum AgentAttributeValue {
    /// Arbitrary string attribute (`TEXT`).
    Text(String),
    /// Fixed-point integer scalar attribute (`SCALAR`).
    Scalar(u64),
    /// Inclusive integer ranges (`RANGES`, e.g., `[(1, 10), (20, 30)]`).
    Ranges(Vec<(u64, u64)>),
    /// Unordered set of string tags (`SET`).
    Set(Vec<String>),
}

/// Typed key-value attribute advertised by an Agent node (Mesos `Attribute`).
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
pub struct AgentAttribute {
    /// Attribute key (e.g., `"rack"`, `"ssd"`, `"kernel"`, `"cpu_family"`).
    pub key: String,
    /// Typed attribute value.
    pub value: AgentAttributeValue,
}

/// Declarative attribute & fault-domain placement constraint (Mesos / Marathon constraint operators).
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
pub enum PlacementConstraint {
    /// Agent must possess an attribute `key` equal to `value` (`(key, value)`).
    Equals(String, AgentAttributeValue),
    /// Agent must not possess an attribute `key` equal to `value` (`(key, value)`).
    NotEquals(String, AgentAttributeValue),
    /// Agent's `Text` attribute `key` must be one of `allowed_values` (or `Set` attribute must intersect `allowed_values`).
    InSet(String, Vec<String>),
    /// At most `max_tasks` tasks of the group may be placed on the same Agent (`MAX_PER` hostname).
    MaxPerHostname(u32),
    /// At most `max_tasks` tasks of the group may be placed in the same availability zone (`MAX_PER` fault domain).
    MaxPerFaultDomain(u32),
}

impl PlacementConstraint {
    /// Evaluates whether an Agent with `attributes`, `existing_tasks_on_host`, and `existing_tasks_in_zone`
    /// satisfies this [`PlacementConstraint`].
    ///
    /// # Arguments
    ///
    /// * `attributes` - Slice of [`AgentAttribute`]s advertised by the candidate Agent.
    /// * `existing_tasks_on_host` - Count of group tasks already placed on this Agent.
    /// * `existing_tasks_in_zone` - Count of group tasks already placed in this Agent's fault-domain zone.
    ///
    /// # Returns
    ///
    /// `true` if the constraint is satisfied.
    pub fn matches_agent(
        &self,
        attributes: &[AgentAttribute],
        existing_tasks_on_host: u32,
        existing_tasks_in_zone: u32,
    ) -> bool {
        match self {
            Self::Equals(key, value) => attributes
                .iter()
                .any(|attr| &attr.key == key && &attr.value == value),
            Self::NotEquals(key, value) => !attributes
                .iter()
                .any(|attr| &attr.key == key && &attr.value == value),
            Self::InSet(key, allowed_values) => attributes.iter().any(|attr| {
                &attr.key == key
                    && match &attr.value {
                        AgentAttributeValue::Text(s) => allowed_values.contains(s),
                        AgentAttributeValue::Set(items) => {
                            items.iter().any(|item| allowed_values.contains(item))
                        }
                        AgentAttributeValue::Scalar(_) | AgentAttributeValue::Ranges(_) => false,
                    }
            }),
            Self::MaxPerHostname(max_tasks) => existing_tasks_on_host < *max_tasks,
            Self::MaxPerFaultDomain(max_tasks) => existing_tasks_in_zone < *max_tasks,
        }
    }
}

/// Sharing mode for a persistent volume mounted across multiple tasks (Mesos `DiskInfo::Persistence` + shared resources).
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
pub enum SharedVolumeMode {
    /// Volume is exclusively mounted by a single task at a time (default).
    #[default]
    Exclusive,
    /// Volume may be shared read-only across multiple co-located tasks.
    SharedReadOnly,
    /// Volume may be shared read-write across multiple co-located tasks.
    SharedReadWrite,
}

/// Backing storage provider source for a persistent volume (Mesos `Resource::DiskInfo::Source`).
#[derive(
    Debug,
    Default,
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
pub enum DiskSource {
    /// Root filesystem subdirectory (`ROOT` disk).
    #[default]
    RootFilesystem,
    /// Shared directory on a secondary disk (`PATH` disk, enforced via project quotas).
    Path(String),
    /// Dedicated pre-formatted filesystem mount (`MOUNT` disk, exclusive whole partition).
    Mount(String),
    /// Raw unformatted block device (`BLOCK` disk, e.g., `/dev/nvme1n1` for databases).
    Block(String),
    /// Raw unallocated storage pool capacity (`RAW` disk waiting for `CREATE_DISK`).
    Raw(String),
    /// Delegated ZFS dataset (`ZfsDataset`, e.g., `"tank/arbiter/vol-1"`).
    ZfsDataset(String),
    /// CSI v1.9 external/local storage volume (`(plugin_name, volume_handle)`).
    CsiVolume(String, String),
}

/// Capabilities advertised by a Mesos v1 Framework (`FrameworkInfo::Capability::Type`).
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
pub enum FrameworkCapability {
    /// Framework can accept and launch tasks on `REVOCABLE_RESOURCES` (oversubscribed / borrowed quota).
    RevocableResources,
    /// Framework handles the `TASK_KILLING` intermediate state prior to `TASK_KILLED`.
    TaskKillingState,
    /// Framework requests and schedules `GPU_RESOURCES` (`nvidia.com/gpu`, `amd.com/gpu`, etc.).
    GpuResources,
    /// Framework can mount `SHARED_RESOURCES` (`SharedVolumeMode::SharedReadOnly` / `SharedReadWrite`).
    SharedResources,
    /// Framework is `PARTITION_AWARE` and handles `TASK_UNREACHABLE`, `TASK_GONE`, and `TASK_GONE_BY_OPERATOR`.
    PartitionAware,
    /// Framework subscribes to multiple scheduling roles simultaneously (`MULTI_ROLE`).
    MultiRole,
    /// Framework supports hierarchical `RESERVATION_REFINEMENT` stacks.
    ReservationRefinement,
    /// Framework can receive offers from remote fault-domain regions (`REGION_AWARE`).
    RegionAware,
}

/// Complete Mesos v1 `FrameworkInfo` descriptor registered with the Master.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize,
)]
pub struct FrameworkInfo {
    /// Unique Framework identifier (`FrameworkID`).
    pub id: FrameworkId,
    /// OS user account under which tasks and executors are launched.
    pub user: String,
    /// Human-readable Framework name.
    pub name: String,
    /// Authenticated security principal of the Framework (`PrincipalName`).
    pub principal: PrincipalName,
    /// Duration the Master retains tasks/state after Framework disconnection (`FailoverTimeoutMillis`).
    pub failover_timeout: FailoverTimeoutMillis,
    /// Whether the Agent checkpoints Framework executor pids and status updates to disk.
    pub checkpoint: CheckpointMode,
    /// Subscribed scheduling roles (`MULTI_ROLE` compatible).
    pub roles: Vec<RoleName>,
    /// Enabled [`FrameworkCapability`] flags.
    pub capabilities: Vec<FrameworkCapability>,
    /// Key-value metadata labels attached to the Framework.
    pub labels: Vec<(String, String)>,
    /// Optional external Web UI URL for operator inspection.
    pub webui_url: Option<String>,
    /// Per-role [`OfferFilter`] configurations active for this Framework.
    pub offer_filters: BTreeMap<RoleName, OfferFilter>,
}

impl FrameworkInfo {
    /// Checks whether this Framework advertises the specified [`FrameworkCapability`].
    ///
    /// # Arguments
    ///
    /// * `capability` - Capability flag to check.
    ///
    /// # Returns
    ///
    /// `true` if `capability` is present in `self.capabilities`.
    pub fn has_capability(&self, capability: FrameworkCapability) -> bool {
        self.capabilities.contains(&capability)
    }
}

/// Capabilities advertised by a Mesos v1 Agent (`AgentInfo::Capability::Type`).
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
pub enum AgentCapability {
    /// Agent supports multi-role frameworks (`MULTI_ROLE`).
    MultiRole,
    /// Agent supports hierarchical scheduling roles (`HIERARCHICAL_ROLE`).
    HierarchicalRole,
    /// Agent supports stacked reservation refinement (`RESERVATION_REFINEMENT`).
    ReservationRefinement,
    /// Agent hosts local CSI / storage resource providers (`RESOURCE_PROVIDER`).
    ResourceProvider,
    /// Agent supports growing and shrinking persistent volumes (`RESIZE_VOLUME`).
    ResizeVolume,
    /// Agent supports nested container hierarchies (`CONTAINERIZER_NESTED`).
    ContainerizerNested,
}

/// Complete Mesos v1 `AgentInfo` descriptor registered with the Master.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize,
)]
pub struct AgentInfo {
    /// Unique Agent identifier (`AgentID`).
    pub id: AgentId,
    /// Routable hostname or IP address of the Agent.
    pub hostname: String,
    /// Control-plane port number of the Agent (`PortNumber`).
    pub port: PortNumber,
    /// Total hardware capacity bundle advertised by the Agent.
    pub resources: ResourceBundle,
    /// Static key-value/scalar/range/set attributes attached to the Agent.
    pub attributes: Vec<AgentAttribute>,
    /// Optional fault domain (`region` and `zone`) of the Agent.
    pub domain: Option<DomainInfo>,
    /// Enabled [`AgentCapability`] flags.
    pub capabilities: Vec<AgentCapability>,
    /// Local storage [`ResourceProviderInfo`] instances hosted on this Agent.
    pub resource_providers: Vec<ResourceProviderInfo>,
}

impl AgentInfo {
    /// Checks whether this Agent advertises the specified [`AgentCapability`].
    ///
    /// # Arguments
    ///
    /// * `capability` - Capability flag to check.
    ///
    /// # Returns
    ///
    /// `true` if `capability` is present in `self.capabilities`.
    pub fn has_capability(&self, capability: AgentCapability) -> bool {
        self.capabilities.contains(&capability)
    }
}

/// Component that originated a [`TaskStatusDetails`] update (`TaskStatus::Source`).
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
pub enum TaskStatusSource {
    /// Generated by the Master (e.g., reconciliation, agent lost, invalid offers).
    SourceMaster,
    /// Generated by the Agent (e.g., container launch failure, cgroup OOM limitation).
    #[default]
    SourceAgent,
    /// Generated by the Executor (e.g., process exit code, health check transition).
    SourceExecutor,
}

/// Canonical Apache Mesos v1 `TaskStatus::Reason` enumeration.
#[derive(
    Debug,
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
pub enum TaskStatusReason {
    /// Built-in command executor failed (`REASON_COMMAND_EXECUTOR_FAILED`).
    ReasonCommandExecutorFailed,
    /// Containerizer failed to launch the container (`REASON_CONTAINER_LAUNCH_FAILED`).
    ReasonContainerLaunchFailed,
    /// Container exceeded its hard CPU quota (`REASON_CONTAINER_LIMITATION_CPU`).
    ReasonContainerLimitationCpu,
    /// Container exceeded its sandbox or volume disk quota (`REASON_CONTAINER_LIMITATION_DISK`).
    ReasonContainerLimitationDisk,
    /// Container triggered a cgroup/job memory OOM limitation (`REASON_CONTAINER_LIMITATION_MEMORY`).
    ReasonContainerLimitationMemory,
    /// Pre-launch hook, artifact fetch, or volume stage failed (`REASON_CONTAINER_PRE_LAUNCH_FAILED`).
    ReasonContainerPreLaunchFailed,
    /// Executor was preempted by the `QoS` or HDRF preemption controller (`REASON_EXECUTOR_PREEMPTED`).
    ReasonExecutorPreempted,
    /// Executor timed out during initial registration (`REASON_EXECUTOR_REGISTRATION_TIMEOUT`).
    ReasonExecutorRegistrationTimeout,
    /// Executor timed out during agent recovery re-registration (`REASON_EXECUTOR_REREGISTRATION_TIMEOUT`).
    ReasonExecutorReregistrationTimeout,
    /// Executor process terminated (`REASON_EXECUTOR_TERMINATED`).
    ReasonExecutorTerminated,
    /// Executor unregistered cleanly (`REASON_EXECUTOR_UNREGISTERED`).
    ReasonExecutorUnregistered,
    /// Owning Framework was torn down or removed (`REASON_FRAMEWORK_REMOVED`).
    ReasonFrameworkRemoved,
    /// Sandbox garbage collection error (`REASON_GC_ERROR`).
    ReasonGcError,
    /// Invalid `FrameworkID` supplied (`REASON_INVALID_FRAMEWORKID`).
    ReasonInvalidFrameworkId,
    /// Offer IDs were expired, rescinded, or invalid (`REASON_INVALID_OFFERS`).
    ReasonInvalidOffers,
    /// Container I/O switchboard process exited unexpectedly (`REASON_IO_SWITCHBOARD_EXITED`).
    ReasonIoSwitchboardExited,
    /// Agent disconnected from Master (`REASON_MASTER_DISCONNECTED`).
    ReasonMasterDisconnected,
    /// Task exceeded its configured `max_completion_time` (`REASON_MAX_COMPLETION_TIME_REACHED`).
    ReasonMaxCompletionTimeReached,
    /// Status update emitted in response to explicit or implicit reconciliation (`REASON_RECONCILIATION`).
    ReasonReconciliation,
    /// Requested resources are unknown on the Agent (`REASON_RESOURCES_UNKNOWN`).
    ReasonResourcesUnknown,
    /// Agent disconnected (`REASON_SLAVE_DISCONNECTED`).
    ReasonAgentDisconnected,
    /// Agent was removed or marked gone (`REASON_SLAVE_REMOVED`).
    ReasonAgentRemoved,
    /// Agent restarted without checkpointing this task (`REASON_SLAVE_RESTARTED`).
    ReasonAgentRestarted,
    /// Agent ID is unknown to the Master (`REASON_SLAVE_UNKNOWN`).
    ReasonAgentUnknown,
    /// General task check (`CheckSpec`) status updated (`REASON_TASK_CHECK_STATUS_UPDATED`).
    ReasonTaskCheckStatusUpdated,
    /// `TaskGroup` specification was invalid (`REASON_TASK_GROUP_INVALID`).
    ReasonTaskGroupInvalid,
    /// Principal is unauthorized to launch the `TaskGroup` (`REASON_TASK_GROUP_UNAUTHORIZED`).
    ReasonTaskGroupUnauthorized,
    /// Task health check (`HealthCheckSpec`) status updated (`REASON_TASK_HEALTH_CHECK_STATUS_UPDATED`).
    ReasonTaskHealthCheckStatusUpdated,
    /// Task specification failed validation (`REASON_TASK_INVALID`).
    ReasonTaskInvalid,
    /// Task was killed while still staging/launching (`REASON_TASK_KILLED_DURING_LAUNCH`).
    ReasonTaskKilledDuringLaunch,
    /// Principal is unauthorized to run the task (`REASON_TASK_UNAUTHORIZED`).
    ReasonTaskUnauthorized,
    /// Task ID is unknown to the Master (`REASON_TASK_UNKNOWN`).
    ReasonTaskUnknown,
}

impl TaskStatusReason {
    /// Returns the canonical Mesos v1 `REASON_*` string identifier for this [`TaskStatusReason`].
    ///
    /// # Returns
    ///
    /// Static Mesos v1 reason code string.
    pub const fn as_mesos_str(self) -> &'static str {
        match self {
            Self::ReasonCommandExecutorFailed => "REASON_COMMAND_EXECUTOR_FAILED",
            Self::ReasonContainerLaunchFailed => "REASON_CONTAINER_LAUNCH_FAILED",
            Self::ReasonContainerLimitationCpu => "REASON_CONTAINER_LIMITATION_CPU",
            Self::ReasonContainerLimitationDisk => "REASON_CONTAINER_LIMITATION_DISK",
            Self::ReasonContainerLimitationMemory => "REASON_CONTAINER_LIMITATION_MEMORY",
            Self::ReasonContainerPreLaunchFailed => "REASON_CONTAINER_PRE_LAUNCH_FAILED",
            Self::ReasonExecutorPreempted => "REASON_EXECUTOR_PREEMPTED",
            Self::ReasonExecutorRegistrationTimeout => "REASON_EXECUTOR_REGISTRATION_TIMEOUT",
            Self::ReasonExecutorReregistrationTimeout => "REASON_EXECUTOR_REREGISTRATION_TIMEOUT",
            Self::ReasonExecutorTerminated => "REASON_EXECUTOR_TERMINATED",
            Self::ReasonExecutorUnregistered => "REASON_EXECUTOR_UNREGISTERED",
            Self::ReasonFrameworkRemoved => "REASON_FRAMEWORK_REMOVED",
            Self::ReasonGcError => "REASON_GC_ERROR",
            Self::ReasonInvalidFrameworkId => "REASON_INVALID_FRAMEWORKID",
            Self::ReasonInvalidOffers => "REASON_INVALID_OFFERS",
            Self::ReasonIoSwitchboardExited => "REASON_IO_SWITCHBOARD_EXITED",
            Self::ReasonMasterDisconnected => "REASON_MASTER_DISCONNECTED",
            Self::ReasonMaxCompletionTimeReached => "REASON_MAX_COMPLETION_TIME_REACHED",
            Self::ReasonReconciliation => "REASON_RECONCILIATION",
            Self::ReasonResourcesUnknown => "REASON_RESOURCES_UNKNOWN",
            Self::ReasonAgentDisconnected => "REASON_SLAVE_DISCONNECTED",
            Self::ReasonAgentRemoved => "REASON_SLAVE_REMOVED",
            Self::ReasonAgentRestarted => "REASON_SLAVE_RESTARTED",
            Self::ReasonAgentUnknown => "REASON_SLAVE_UNKNOWN",
            Self::ReasonTaskCheckStatusUpdated => "REASON_TASK_CHECK_STATUS_UPDATED",
            Self::ReasonTaskGroupInvalid => "REASON_TASK_GROUP_INVALID",
            Self::ReasonTaskGroupUnauthorized => "REASON_TASK_GROUP_UNAUTHORIZED",
            Self::ReasonTaskHealthCheckStatusUpdated => "REASON_TASK_HEALTH_CHECK_STATUS_UPDATED",
            Self::ReasonTaskInvalid => "REASON_TASK_INVALID",
            Self::ReasonTaskKilledDuringLaunch => "REASON_TASK_KILLED_DURING_LAUNCH",
            Self::ReasonTaskUnauthorized => "REASON_TASK_UNAUTHORIZED",
            Self::ReasonTaskUnknown => "REASON_TASK_UNKNOWN",
        }
    }
}

/// Command check payload for [`CheckSpec::Command`] (`CheckInfo::Command`).
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
pub struct CheckCommandSpec {
    /// Command binary or shell string.
    pub command: String,
    /// Command-line arguments.
    pub args: Vec<String>,
    /// Check execution interval in milliseconds.
    pub interval_ms: u64,
    /// Per-invocation timeout in milliseconds.
    pub timeout_ms: u64,
}

/// HTTP GET check payload for [`CheckSpec::Http`] (`CheckInfo::Http`).
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
pub struct CheckHttpSpec {
    /// Target TCP port (`PortNumber`).
    pub port: PortNumber,
    /// Request URI path (e.g., `"/readyz"`).
    pub path: String,
    /// Check execution interval in milliseconds.
    pub interval_ms: u64,
    /// Per-invocation timeout in milliseconds.
    pub timeout_ms: u64,
}

/// TCP handshake check payload for [`CheckSpec::Tcp`] (`CheckInfo::Tcp`).
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
pub struct CheckTcpSpec {
    /// Target TCP port (`PortNumber`).
    pub port: PortNumber,
    /// Check execution interval in milliseconds.
    pub interval_ms: u64,
    /// Per-invocation timeout in milliseconds.
    pub timeout_ms: u64,
}

/// General task check specification (`Mesos CheckInfo`, distinct from kill-triggering `HealthCheckSpec`).
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
pub enum CheckSpec {
    /// Executes a command inside the task's mount/network namespace (`CheckInfo::Command`).
    Command(CheckCommandSpec),
    /// Performs an HTTP GET request against the task (`CheckInfo::Http`).
    Http(CheckHttpSpec),
    /// Performs a TCP 3-way handshake probe against the task (`CheckInfo::Tcp`).
    Tcp(CheckTcpSpec),
}

/// Latest observed result of a [`CheckSpec`] (`Mesos CheckStatusInfo`).
#[derive(
    Debug,
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
pub enum CheckStatusInfo {
    /// Exit status code from a `CheckSpec::Command` (`CheckStatusInfo::Command`).
    Command(ExitCode),
    /// HTTP status code (`u16`) from a `CheckSpec::Http` (`CheckStatusInfo::Http`).
    Http(u16),
    /// Whether the TCP handshake succeeded (`CheckStatusInfo::Tcp`).
    Tcp(bool),
}

/// Enriched Mesos v1 `TaskStatus` metadata (`TaskStatusDetails`) carrying source, reason,
/// check results, cgroup limitations, container IP/IDs, and partition timestamps.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize,
)]
pub struct TaskStatusDetails {
    /// Component that generated the status update (`SourceMaster`, `SourceAgent`, `SourceExecutor`).
    pub source: TaskStatusSource,
    /// Optional structured [`TaskStatusReason`].
    pub reason: Option<TaskStatusReason>,
    /// Optional idempotency UUID requiring Framework `ACKNOWLEDGE`.
    pub uuid: Option<StatusUpdateUuid>,
    /// Optional latest health check state (`true` = healthy, `false` = unhealthy).
    pub healthy: Option<bool>,
    /// Optional latest general check result (`CheckStatusInfo`).
    pub check_status: Option<CheckStatusInfo>,
    /// Optional resource bundle that triggered a container limitation (`REASON_CONTAINER_LIMITATION_*`).
    pub limitation: Option<ResourceBundle>,
    /// Optional container ID associated with the running task.
    pub container_id: Option<ContainerId>,
    /// Wall-clock timestamp when the status update was generated (`WallClockUnixMillis`).
    pub timestamp: WallClockUnixMillis,
    /// Optional wall-clock timestamp when the hosting Agent became unreachable (`WallClockUnixMillis`).
    pub unreachable_time: Option<WallClockUnixMillis>,
}

/// Strongly-typed Mesos v1 `WeightInfo` operator entry pairing a [`RoleName`] with its [`WeightBasisPoints`].
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
pub struct WeightInfo {
    /// Scheduling role name.
    pub role: RoleName,
    /// Relative HDRF fairness weight in basis points (`WeightBasisPoints`).
    pub weight: WeightBasisPoints,
}

/// Strongly-typed Mesos v1 `QuotaConfig` operator specification for `UPDATE_QUOTA`.
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
pub struct QuotaConfig {
    /// Scheduling role name to which this quota applies.
    pub role: RoleName,
    /// Guaranteed minimum resource bundle (`guarantees`).
    pub guarantees: ResourceBundle,
    /// Hard maximum resource bundle (`limits`).
    pub limits: ResourceBundle,
    /// Whether the Master should apply the quota even if currently overcommitted (`force`).
    pub force: bool,
}

impl QuotaConfig {
    /// Validates and converts this [`QuotaConfig`] into a [`Quota`] policy.
    ///
    /// # Arguments
    ///
    /// * `quota_id` - Unique [`QuotaId`] for the resulting [`Quota`].
    /// * `weight` - Role fairness weight in [`WeightBasisPoints`].
    ///
    /// # Returns
    ///
    /// Validated [`Quota`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::InvalidQuotaBounds`] if `limits` does not contain `guarantees` (unless `self.force` is true).
    pub fn into_quota(self, quota_id: QuotaId, weight: WeightBasisPoints) -> ArbiterResult<Quota> {
        if self.force {
            Ok(Quota {
                id: quota_id,
                guaranteed_min: self.guarantees,
                hard_max: self.limits,
                allow_burst_borrowing: true,
                weight,
            })
        } else {
            Quota::new(
                quota_id,
                &self.role,
                self.guarantees,
                self.limits,
                true,
                weight,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::units::Millicores;

    #[test]
    #[allow(clippy::too_many_lines)]
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

        // Child role whose hard_max exceeds parent role's hard_max -> InvalidQuotaBounds
        let mut excessive_child_max = ResourceBundle::zero();
        excessive_child_max.cpu = Millicores::new(999_000);
        assert!(
            hierarchy
                .add_role(Role {
                    name: RoleName(String::from("prod.excessive")),
                    parent: Some(r_prod.clone()),
                    quota: Quota {
                        id: QuotaId(String::from("q-exc")),
                        guaranteed_min: ResourceBundle::zero(),
                        hard_max: excessive_child_max,
                        allow_burst_borrowing: true,
                        weight: WeightBasisPoints::STANDARD,
                    },
                })
                .is_err()
        );

        // Add child role with valid parent
        assert!(
            hierarchy
                .add_role(Role {
                    name: r_ml.clone(),
                    parent: Some(r_prod.clone()),
                    quota: quota_val.clone(),
                })
                .is_ok()
        );
        // Second sibling under parent covers sibling iteration in add_role
        assert!(
            hierarchy
                .add_role(Role {
                    name: RoleName(String::from("prod.db")),
                    parent: Some(r_prod.clone()),
                    quota: quota_val,
                })
                .is_ok()
        );

        assert_eq!(hierarchy.roles().len(), 3);
        assert!(hierarchy.get_role(&r_prod).is_ok());
        assert!(hierarchy.get_role(&r_ml).is_ok());
        assert!(hierarchy.get_role(&r_missing).is_err());

        // Test set_role_quota, remove_role_quota, and update_role_weight
        let mut bad_max = ResourceBundle::zero();
        bad_max.cpu = Millicores::new(1000);
        let mut high_min = ResourceBundle::zero();
        high_min.cpu = Millicores::new(5000);
        assert!(
            hierarchy
                .set_role_quota(
                    &r_prod,
                    Quota {
                        id: QuotaId(String::from("q-bad")),
                        guaranteed_min: high_min,
                        hard_max: bad_max,
                        allow_burst_borrowing: true,
                        weight: WeightBasisPoints::STANDARD,
                    },
                )
                .is_err()
        );

        let mut new_max = ResourceBundle::zero();
        new_max.cpu = Millicores::new(20_000);
        let valid_q = Quota {
            id: QuotaId(String::from("q-updated")),
            guaranteed_min: ResourceBundle::zero(),
            hard_max: new_max,
            allow_burst_borrowing: true,
            weight: WeightBasisPoints::STANDARD,
        };
        assert!(hierarchy.set_role_quota(&r_prod, valid_q.clone()).is_ok());
        let r_new = RoleName(String::from("analytics"));
        assert!(hierarchy.set_role_quota(&r_new, valid_q).is_ok());
        assert_eq!(hierarchy.roles().len(), 4);

        let w_double = WeightBasisPoints::new(20_000).unwrap_or(WeightBasisPoints::STANDARD);
        assert!(hierarchy.update_role_weight(&r_prod, w_double).is_ok());
        assert!(hierarchy.update_role_weight(&r_missing, w_double).is_err());
        assert!(hierarchy.remove_role_quota(&r_prod).is_ok());
        assert!(hierarchy.remove_role_quota(&r_missing).is_err());
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
            TaskState::Unreachable,
            TaskState::Finished,
            TaskState::Failed,
            TaskState::Killed,
            TaskState::Error,
            TaskState::Dropped,
            TaskState::Lost,
            TaskState::Gone,
            TaskState::GoneByOperator,
            TaskState::Unknown,
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
        assert!(
            TaskState::Unreachable
                .validate_transition(TaskState::Running)
                .is_ok()
        );
        assert!(
            TaskState::Unreachable
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
            TaskState::Unreachable,
        ] {
            assert!(!non_term.is_terminal());
            for target in [
                TaskState::Failed,
                TaskState::Killed,
                TaskState::Error,
                TaskState::Dropped,
                TaskState::Lost,
                TaskState::Killing,
                TaskState::Unreachable,
                TaskState::Gone,
                TaskState::GoneByOperator,
            ] {
                assert!(non_term.validate_transition(target).is_ok());
            }
        }

        for term in [
            TaskState::Finished,
            TaskState::Failed,
            TaskState::Killed,
            TaskState::Error,
            TaskState::Dropped,
            TaskState::Lost,
            TaskState::Gone,
            TaskState::GoneByOperator,
            TaskState::Unknown,
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
        assert_eq!(CheckpointMode::default(), CheckpointMode::Enabled);
        assert_eq!(
            DrainCompletionMode::default(),
            DrainCompletionMode::RemainDrained
        );
        assert_eq!(
            InverseOfferResponse::default(),
            InverseOfferResponse::AcceptMaintenance
        );
        assert!(InverseOfferResponse::from_bool(true).is_accepted());
        assert!(!InverseOfferResponse::from_bool(false).is_accepted());
        let _ = rkyv::to_bytes::<rkyv::rancor::Error>(&InverseOfferResponse::DeclineMaintenance);
        assert_eq!(
            AgentMaintenanceState::default(),
            AgentMaintenanceState::Normal
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        clippy::type_complexity,
        clippy::items_after_statements
    )]
    fn test_domain_info_attributes_and_placement_constraints() {
        let r_east = RegionName::new("us-east-1").unwrap_or_default();
        let r_west = RegionName::new("us-west-2").unwrap_or_default();
        let z_1a = ZoneName::new("us-east-1a").unwrap_or_default();
        let dom_east = DomainInfo::new(r_east.clone(), z_1a.clone());
        let dom_east2 = DomainInfo::new(r_east, z_1a);
        let dom_west = DomainInfo::new(r_west, ZoneName::new("us-west-2a").unwrap_or_default());
        assert!(!dom_east.is_remote_region(&dom_east2));
        assert!(dom_east.is_remote_region(&dom_west));
        assert_eq!(DomainInfo::default().fault_domain.region.as_str(), "");

        let attrs = vec![
            AgentAttribute {
                key: "rack".to_owned(),
                value: AgentAttributeValue::Text("r1".to_owned()),
            },
            AgentAttribute {
                key: "features".to_owned(),
                value: AgentAttributeValue::Set(vec!["nvme".to_owned(), "rdma".to_owned()]),
            },
            AgentAttribute {
                key: "gen".to_owned(),
                value: AgentAttributeValue::Scalar(5),
            },
            AgentAttribute {
                key: "vlans".to_owned(),
                value: AgentAttributeValue::Ranges(vec![(100, 200)]),
            },
        ];

        for c_ok in [
            PlacementConstraint::Equals("gen".to_owned(), AgentAttributeValue::Scalar(5)),
            PlacementConstraint::NotEquals(
                "rack".to_owned(),
                AgentAttributeValue::Text("r2".to_owned()),
            ),
            PlacementConstraint::InSet("rack".to_owned(), vec!["r1".to_owned(), "r3".to_owned()]),
            PlacementConstraint::InSet("features".to_owned(), vec!["rdma".to_owned()]),
            PlacementConstraint::MaxPerHostname(2),
            PlacementConstraint::MaxPerFaultDomain(3),
        ] {
            assert!(c_ok.matches_agent(&attrs, 1, 2));
        }

        for c_fail in [
            PlacementConstraint::InSet("gen".to_owned(), vec!["5".to_owned()]),
            PlacementConstraint::InSet("vlans".to_owned(), vec!["100".to_owned()]),
            PlacementConstraint::MaxPerHostname(1),
            PlacementConstraint::MaxPerFaultDomain(2),
        ] {
            assert!(!c_fail.matches_agent(&attrs, 1, 2));
        }

        assert_eq!(SharedVolumeMode::default(), SharedVolumeMode::Exclusive);
        assert_eq!(DiskSource::default(), DiskSource::RootFilesystem);

        let default_filter = OfferFilter::default();
        assert_eq!(
            default_filter.expiration_tick(BenchmarkTicks::new(10)),
            BenchmarkTicks::new(15)
        );
        assert!(default_filter.is_active_at(BenchmarkTicks::new(10), BenchmarkTicks::new(14)));
        assert!(!default_filter.is_active_at(BenchmarkTicks::new(10), BenchmarkTicks::new(15)));

        let subsecond_filter = OfferFilter {
            refuse_milliseconds: 500,
            min_cpu_millicores: 2000,
            min_memory_bytes: Bytes::new(1024),
            refuse_gpu_offers: true,
            min_gpu_vram: Bytes::new(512),
        };
        assert_eq!(
            subsecond_filter.expiration_tick(BenchmarkTicks::new(10)),
            BenchmarkTicks::new(11)
        );
        let multi_sec_filter = OfferFilter {
            refuse_milliseconds: 3000,
            ..subsecond_filter
        };
        assert_eq!(
            multi_sec_filter.expiration_tick(BenchmarkTicks::new(10)),
            BenchmarkTicks::new(13)
        );

        let mut bundle = ResourceBundle::zero();
        assert!(!subsecond_filter.allows_bundle(&bundle));
        bundle.cpu = Millicores::new(2000);
        assert!(!subsecond_filter.allows_bundle(&bundle));
        bundle.memory = Bytes::new(1024);
        bundle.gpu_compute = crate::units::GpuMillicores::new(1000);
        assert!(!subsecond_filter.allows_bundle(&bundle));
        bundle.gpu_compute = crate::units::GpuMillicores::ZERO;
        assert!(!subsecond_filter.allows_bundle(&bundle));
        bundle.gpu_vram = Bytes::new(512);
        assert!(subsecond_filter.allows_bundle(&bundle));
        let allow_gpu_filter = OfferFilter {
            refuse_gpu_offers: false,
            ..subsecond_filter
        };
        bundle.gpu_compute = crate::units::GpuMillicores::new(1000);
        assert!(allow_gpu_filter.allows_bundle(&bundle));

        let rkyv_w1 = (
            RoleHierarchy::new(),
            Role {
                name: RoleName::default(),
                parent: None,
                quota: Quota {
                    id: QuotaId::default(),
                    guaranteed_min: ResourceBundle::zero(),
                    hard_max: ResourceBundle::zero(),
                    allow_burst_borrowing: false,
                    weight: WeightBasisPoints::STANDARD,
                },
            },
            TaskGroupSpec {
                group_id: TaskGroupId::default(),
                role: RoleName::default(),
                tasks: vec![TaskSpec {
                    task_id: TaskId::default(),
                    role: RoleName::default(),
                    framework_id: None,
                    priority: PriorityClass::Batch,
                    preemption_policy: PreemptionPolicy::ImmediateKill,
                    resources: ResourceBundle::zero(),
                    required_gpu_vendor: None,
                    required_gpu_partition: None,
                    topology_constraints: vec![
                        TopologyConstraint::TpuTorusContiguous(
                            crate::resources::TpuTopologySlice {
                                slice_id: crate::ids::SliceId::default(),
                                generation: crate::resources::TpuGeneration::CloudTpuV4,
                                dim_x: 1,
                                dim_y: 1,
                                dim_z: 1,
                                require_wrap_around: false,
                            },
                        ),
                        TopologyConstraint::ExtendedRequirements(Box::default()),
                    ],
                    election_group: None,
                    isolation: IsolationSpec {
                        capabilities: Vec::new(),
                        image_ref: None,
                        command: String::new(),
                        args: Vec::new(),
                        env: Vec::new(),
                        run_as_user: None,
                    },
                    artifacts: vec![ArtifactSpec {
                        uri: String::new(),
                        sha256_hex: String::new(),
                        extract: false,
                        executable: false,
                    }],
                    secrets: vec![SecretMountSpec {
                        secret_id: SecretId::default(),
                        mount_path: String::new(),
                    }],
                    health_check: Some(HealthCheckSpec {
                        protocol: HealthCheckProtocol::HttpGet("a".to_owned()),
                        port: PortNumber::default(),
                        interval_ms: 1,
                        timeout_ms: 1,
                        unhealthy_threshold: 1,
                    }),
                }],
                tpu_slice: None,
                placement_timeout_ms: 1,
            },
            OfferFilter::default(),
            ResourceOffer {
                offer_id: OfferId::default(),
                framework_id: FrameworkId::default(),
                agent_id: AgentId::default(),
                role: RoleName::default(),
                resources: ResourceBundle::zero(),
                revocable: false,
                expires_at_tick: 0,
            },
            vec![
                OfferOperation::LaunchTask(Box::new(TaskSpec {
                    task_id: TaskId::default(),
                    role: RoleName::default(),
                    framework_id: None,
                    priority: PriorityClass::Batch,
                    preemption_policy: PreemptionPolicy::ImmediateKill,
                    resources: ResourceBundle::zero(),
                    required_gpu_vendor: None,
                    required_gpu_partition: None,
                    topology_constraints: Vec::new(),
                    election_group: None,
                    isolation: IsolationSpec {
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
                })),
                OfferOperation::CreateVolume(VolumeReservationSpec {
                    volume_id: VolumeId::default(),
                    capacity: Bytes::ZERO,
                    container_path: String::new(),
                }),
                OfferOperation::GrowVolume(VolumeId::default(), Bytes::ZERO),
                OfferOperation::ShrinkVolume(VolumeId::default(), Bytes::ZERO),
                OfferOperation::CreateDisk(ResourceProviderDiskSpec {
                    provider_id: ResourceProviderId::default(),
                    volume_id: VolumeId::default(),
                    source: DiskSource::Path("a".to_owned()),
                    capacity: Bytes::ZERO,
                }),
            ],
            ResourceProviderInfo {
                provider_id: ResourceProviderId::default(),
                agent_id: None,
                provider_type: String::new(),
                provider_name: String::new(),
                default_role: RoleName::default(),
                advertised_disks: Vec::new(),
            },
        );
        let rkyv_w2 = (
            ExecutorInfo {
                executor_id: ExecutorId::default(),
                agent_id: AgentId::default(),
            },
            KillPolicy {
                grace_period_ticks: crate::units::BenchmarkTicks::new(1),
            },
            InverseOffer {
                inverse_offer_id: OfferId::default(),
                framework_id: FrameworkId::default(),
                agent_id: AgentId::default(),
                maintenance_window_id: MaintenanceWindowId::default(),
                resources: ResourceBundle::zero(),
                unavailability_start_tick: crate::units::BenchmarkTicks::new(0),
            },
            DynamicReservationSpec {
                operation_id: OperationId::default(),
                agent_id: AgentId::default(),
                role: RoleName::default(),
                resources: ResourceBundle::zero(),
                principal: String::new(),
            },
            MaintenanceSchedule {
                windows: vec![MaintenanceWindow {
                    window_id: MaintenanceWindowId::default(),
                    agent_ids: Vec::new(),
                    unavailability_start_tick: crate::units::BenchmarkTicks::new(0),
                    duration_ticks: crate::units::BenchmarkTicks::new(1),
                }],
            },
            vec![
                AgentMaintenanceState::ScheduledForMaintenance(MaintenanceWindowId::default()),
                AgentMaintenanceState::Draining(DrainingSpec {
                    completion_mode: DrainCompletionMode::RemainDrained,
                    grace_period_ticks: crate::units::BenchmarkTicks::new(1),
                }),
            ],
            ResourceRequest {
                agent_id: None,
                resources: ResourceBundle::zero(),
            },
            MasterInfo {
                leader_id: String::new(),
                version: String::new(),
                elected_term: 1,
            },
            dom_east,
            attrs,
            PlacementConstraint::Equals(String::new(), AgentAttributeValue::Text(String::new())),
        );
        let rkyv_w_bytes =
            rkyv::to_bytes::<rkyv::rancor::Error>(&(rkyv_w1, rkyv_w2)).unwrap_or_default();
        type WorkloadRkyvTuple = (
            (
                RoleHierarchy,
                Role,
                TaskGroupSpec,
                OfferFilter,
                ResourceOffer,
                Vec<OfferOperation>,
                ResourceProviderInfo,
            ),
            (
                ExecutorInfo,
                KillPolicy,
                InverseOffer,
                DynamicReservationSpec,
                MaintenanceSchedule,
                Vec<AgentMaintenanceState>,
                ResourceRequest,
                MasterInfo,
                DomainInfo,
                Vec<AgentAttribute>,
                PlacementConstraint,
            ),
        );
        for i in 0..rkyv_w_bytes.len() {
            let mut corrupted = rkyv_w_bytes.clone();
            for (j, b) in corrupted.iter_mut().enumerate() {
                if i == j {
                    *b ^= 0xFF;
                }
            }
            let _: Result<WorkloadRkyvTuple, rkyv::rancor::Error> = rkyv::from_bytes(&corrupted);
        }
        let _: Result<WorkloadRkyvTuple, rkyv::rancor::Error> = rkyv::from_bytes(&rkyv_w_bytes);
    }

    #[test]
    fn test_role_hierarchy_guaranteed_min_ceiling() {
        let r_parent = RoleName::new("root-dept").unwrap_or_default();
        let r_child = RoleName::new("root-dept.sub").unwrap_or_default();
        let mut h = RoleHierarchy::new();
        let mut parent_min = ResourceBundle::zero();
        parent_min.cpu = Millicores::new(4_000);
        let mut parent_max = ResourceBundle::zero();
        parent_max.cpu = Millicores::new(16_000);
        assert!(
            h.add_role(Role {
                name: r_parent.clone(),
                parent: None,
                quota: Quota {
                    id: QuotaId::new("q-p").unwrap_or_default(),
                    guaranteed_min: parent_min,
                    hard_max: parent_max.clone(),
                    allow_burst_borrowing: true,
                    weight: WeightBasisPoints::STANDARD,
                },
            })
            .is_ok()
        );
        let mut child_min_excess = ResourceBundle::zero();
        child_min_excess.cpu = Millicores::new(8_000);
        assert!(
            h.add_role(Role {
                name: r_child.clone(),
                parent: Some(r_parent.clone()),
                quota: Quota {
                    id: QuotaId::new("q-c-bad").unwrap_or_default(),
                    guaranteed_min: child_min_excess,
                    hard_max: parent_max.clone(),
                    allow_burst_borrowing: true,
                    weight: WeightBasisPoints::STANDARD,
                },
            })
            .is_err()
        );
        let mut child_min_ok = ResourceBundle::zero();
        child_min_ok.cpu = Millicores::new(2_000);
        assert!(
            h.add_role(Role {
                name: r_child,
                parent: Some(r_parent),
                quota: Quota {
                    id: QuotaId::new("q-c-ok").unwrap_or_default(),
                    guaranteed_min: child_min_ok,
                    hard_max: parent_max,
                    allow_burst_borrowing: true,
                    weight: WeightBasisPoints::STANDARD,
                },
            })
            .is_ok()
        );
    }

    #[test]
    fn test_task_scheduling_requirements_and_accessors() {
        let r_parent = RoleName::new("root-dept").unwrap_or_default();
        let mut base_bundle = ResourceBundle::zero();
        base_bundle.cpu = Millicores::new(2_000);
        base_bundle.memory = Bytes::new(4_096);
        base_bundle.disk = Bytes::new(8_192);
        base_bundle.network_bandwidth = crate::units::BandwidthBps::new(100_000);
        let mut base_task = TaskSpec {
            task_id: TaskId::new("t-sched").unwrap_or_default(),
            role: r_parent,
            framework_id: None,
            election_group: None,
            priority: PriorityClass::ProductionStandard,
            preemption_policy: PreemptionPolicy::GracefulSigterm,
            resources: base_bundle,
            required_gpu_vendor: None,
            required_gpu_partition: None,
            topology_constraints: vec![TopologyConstraint::SameNuma],
            isolation: IsolationSpec {
                capabilities: Vec::new(),
                image_ref: None,
                command: "/bin/app".to_owned(),
                args: Vec::new(),
                env: Vec::new(),
                run_as_user: None,
            },
            artifacts: Vec::new(),
            secrets: Vec::new(),
            health_check: None,
        };
        assert!(TaskSchedulingRequirements::from_task(&base_task).is_none());
        assert_eq!(base_task.cpu_requirements().millicores.get(), 2_000);
        assert_eq!(base_task.memory_requirements().ram_bytes.get(), 4_096);
        assert_eq!(base_task.storage_requirements().capacity_bytes.get(), 8_192);
        assert_eq!(base_task.network_requirements().ingress_bps.get(), 100_000);
        assert!(base_task.placement_constraints().is_empty());
        assert!(base_task.fault_domain_preference().is_none());
        assert!(base_task.shared_volume_mounts().is_empty());
        assert_eq!(base_task.kill_policy(), KillPolicy::default());
        assert!(base_task.executor_info().is_none());

        let port_range = crate::units::PortRange::new(
            PortNumber::new(8080).unwrap_or_default(),
            PortNumber::new(8081).unwrap_or_default(),
        )
        .into_iter()
        .collect();
        let custom_reqs = TaskSchedulingRequirements {
            cpu_resource: Some(CpuResource {
                millicores: Millicores::new(4_000),
                preferred_core_class: None,
                required_extensions: Vec::new(),
            }),
            memory_resource: Some(MemoryResource {
                ram_bytes: Bytes::new(16_384),
                hugepages_2mib_bytes: Bytes::ZERO,
                hugepages_1gib_bytes: Bytes::ZERO,
                require_unified_memory: false,
            }),
            storage_resource: Some(StorageResource {
                capacity_bytes: Bytes::new(65_536),
                max_iops: 10_000,
                throughput_bps: crate::units::BandwidthBps::new(500_000),
                disk_class: Some(crate::resources::DiskClass::Nvme),
            }),
            network_resource: Some(NetworkResource {
                ingress_bps: crate::units::BandwidthBps::new(200_000),
                egress_bps: crate::units::BandwidthBps::new(200_000),
                ports: crate::units::PortSet::from_ranges(port_range),
                rdma_vfs: 2,
            }),
            placement_constraints: vec![PlacementConstraint::MaxPerHostname(2)],
            required_domain: Some(DomainInfo::default()),
            shared_volume_mounts: vec![(VolumeId::default(), SharedVolumeMode::SharedReadOnly)],
            kill_policy: KillPolicy {
                grace_period_ticks: BenchmarkTicks::new(15),
            },
            executor_info: Some(ExecutorInfo {
                executor_id: ExecutorId::default(),
                agent_id: AgentId::default(),
            }),
        };
        let legacy_json = serde_json::to_string(&custom_reqs).unwrap_or_default();
        base_task.isolation.env.push((
            ARBITER_SCHEDULING_REQUIREMENTS_ENV_KEY.to_owned(),
            legacy_json,
        ));
        assert_eq!(
            TaskSchedulingRequirements::from_task(&base_task),
            Some(custom_reqs.clone())
        );

        let enriched = base_task.with_scheduling_requirements(&custom_reqs);
        assert_eq!(enriched.cpu_requirements().millicores.get(), 4_000);
        assert_eq!(enriched.memory_requirements().ram_bytes.get(), 16_384);
        assert_eq!(enriched.storage_requirements().capacity_bytes.get(), 65_536);
        assert_eq!(enriched.network_requirements().ingress_bps.get(), 200_000);
        assert_eq!(enriched.network_requirements().ports.total_ports(), 2);
        assert_eq!(enriched.placement_constraints().len(), 1);
        assert!(enriched.fault_domain_preference().is_some());
        assert_eq!(enriched.shared_volume_mounts().len(), 1);
        assert_eq!(enriched.kill_policy().grace_period_ticks.get(), 15);
        assert!(enriched.executor_info().is_some());
    }

    #[test]
    #[allow(clippy::too_many_lines, clippy::items_after_statements)]
    fn test_mesos_v1_framework_agent_info_reasons_checks_and_quota_config() {
        let role = RoleName::new("ml-prod").unwrap_or_default();
        let fw_info = FrameworkInfo {
            id: FrameworkId::new("fw-mesos-1").unwrap_or_default(),
            user: "root".to_owned(),
            name: "PyTorch-Elastic".to_owned(),
            principal: PrincipalName::new("spiffe://cluster.local/ns/ml/sa/trainer")
                .unwrap_or_default(),
            failover_timeout: FailoverTimeoutMillis::new(60_000),
            checkpoint: CheckpointMode::Enabled,
            roles: vec![role.clone()],
            capabilities: vec![
                FrameworkCapability::RevocableResources,
                FrameworkCapability::TaskKillingState,
                FrameworkCapability::GpuResources,
                FrameworkCapability::SharedResources,
                FrameworkCapability::PartitionAware,
                FrameworkCapability::MultiRole,
                FrameworkCapability::ReservationRefinement,
                FrameworkCapability::RegionAware,
            ],
            labels: vec![("env".to_owned(), "prod".to_owned())],
            webui_url: Some("https://fw.arbiter.internal".to_owned()),
            offer_filters: BTreeMap::from([(role.clone(), OfferFilter::default())]),
        };
        assert!(fw_info.has_capability(FrameworkCapability::GpuResources));

        let ag_info = AgentInfo {
            id: AgentId::new("agent-mesos-1").unwrap_or_default(),
            hostname: "node01.arbiter.internal".to_owned(),
            port: PortNumber::new(5051).unwrap_or_default(),
            resources: ResourceBundle::zero(),
            attributes: Vec::new(),
            domain: Some(DomainInfo::default()),
            capabilities: vec![
                AgentCapability::MultiRole,
                AgentCapability::HierarchicalRole,
                AgentCapability::ReservationRefinement,
                AgentCapability::ResourceProvider,
                AgentCapability::ResizeVolume,
                AgentCapability::ContainerizerNested,
            ],
            resource_providers: Vec::new(),
        };
        assert!(ag_info.has_capability(AgentCapability::ContainerizerNested));

        let all_reasons = [
            TaskStatusReason::ReasonCommandExecutorFailed,
            TaskStatusReason::ReasonContainerLaunchFailed,
            TaskStatusReason::ReasonContainerLimitationCpu,
            TaskStatusReason::ReasonContainerLimitationDisk,
            TaskStatusReason::ReasonContainerLimitationMemory,
            TaskStatusReason::ReasonContainerPreLaunchFailed,
            TaskStatusReason::ReasonExecutorPreempted,
            TaskStatusReason::ReasonExecutorRegistrationTimeout,
            TaskStatusReason::ReasonExecutorReregistrationTimeout,
            TaskStatusReason::ReasonExecutorTerminated,
            TaskStatusReason::ReasonExecutorUnregistered,
            TaskStatusReason::ReasonFrameworkRemoved,
            TaskStatusReason::ReasonGcError,
            TaskStatusReason::ReasonInvalidFrameworkId,
            TaskStatusReason::ReasonInvalidOffers,
            TaskStatusReason::ReasonIoSwitchboardExited,
            TaskStatusReason::ReasonMasterDisconnected,
            TaskStatusReason::ReasonMaxCompletionTimeReached,
            TaskStatusReason::ReasonReconciliation,
            TaskStatusReason::ReasonResourcesUnknown,
            TaskStatusReason::ReasonAgentDisconnected,
            TaskStatusReason::ReasonAgentRemoved,
            TaskStatusReason::ReasonAgentRestarted,
            TaskStatusReason::ReasonAgentUnknown,
            TaskStatusReason::ReasonTaskCheckStatusUpdated,
            TaskStatusReason::ReasonTaskGroupInvalid,
            TaskStatusReason::ReasonTaskGroupUnauthorized,
            TaskStatusReason::ReasonTaskHealthCheckStatusUpdated,
            TaskStatusReason::ReasonTaskInvalid,
            TaskStatusReason::ReasonTaskKilledDuringLaunch,
            TaskStatusReason::ReasonTaskUnauthorized,
            TaskStatusReason::ReasonTaskUnknown,
        ];
        for r in all_reasons {
            assert!(r.as_mesos_str().starts_with("REASON_"));
        }

        assert_eq!(TaskStatusSource::default(), TaskStatusSource::SourceAgent);
        let checks = vec![
            CheckSpec::Command(CheckCommandSpec {
                command: "/bin/true".to_owned(),
                args: Vec::new(),
                interval_ms: 1000,
                timeout_ms: 500,
            }),
            CheckSpec::Http(CheckHttpSpec {
                port: PortNumber::new(8080).unwrap_or_default(),
                path: "/readyz".to_owned(),
                interval_ms: 1000,
                timeout_ms: 500,
            }),
            CheckSpec::Tcp(CheckTcpSpec {
                port: PortNumber::new(5432).unwrap_or_default(),
                interval_ms: 1000,
                timeout_ms: 500,
            }),
        ];
        let details = TaskStatusDetails {
            source: TaskStatusSource::SourceExecutor,
            reason: Some(TaskStatusReason::ReasonTaskCheckStatusUpdated),
            uuid: Some(StatusUpdateUuid::new("uuid-1").unwrap_or_default()),
            healthy: Some(true),
            check_status: Some(CheckStatusInfo::Http(200)),
            limitation: None,
            container_id: Some(ContainerId::new("c-1").unwrap_or_default()),
            timestamp: WallClockUnixMillis::new(1_700_000_000_000),
            unreachable_time: None,
        };
        let weight_info = WeightInfo {
            role: role.clone(),
            weight: WeightBasisPoints::STANDARD,
        };

        let mut g_bundle = ResourceBundle::zero();
        g_bundle.cpu = Millicores::new(4_000);
        let mut l_bundle = ResourceBundle::zero();
        l_bundle.cpu = Millicores::new(2_000);

        let qc_unforced = QuotaConfig {
            role: role.clone(),
            guarantees: g_bundle.clone(),
            limits: l_bundle.clone(),
            force: false,
        };
        assert!(
            qc_unforced
                .into_quota(QuotaId::default(), WeightBasisPoints::STANDARD)
                .is_err()
        );

        let qc_forced = QuotaConfig {
            role: role.clone(),
            guarantees: g_bundle.clone(),
            limits: l_bundle,
            force: true,
        };
        assert!(
            qc_forced
                .into_quota(QuotaId::default(), WeightBasisPoints::STANDARD)
                .is_ok()
        );

        let mut ok_limits = ResourceBundle::zero();
        ok_limits.cpu = Millicores::new(8_000);
        let qc_valid = QuotaConfig {
            role,
            guarantees: g_bundle,
            limits: ok_limits,
            force: false,
        };
        let valid_quota = qc_valid
            .clone()
            .into_quota(QuotaId::default(), WeightBasisPoints::STANDARD);
        assert!(valid_quota.is_ok());

        let rkyv_extra = (
            fw_info,
            ag_info,
            checks,
            vec![
                CheckStatusInfo::Command(ExitCode::SUCCESS),
                CheckStatusInfo::Http(200),
                CheckStatusInfo::Tcp(true),
            ],
            details,
            weight_info,
            qc_valid,
            vec![
                TaskStatusSource::SourceMaster,
                TaskStatusSource::SourceAgent,
                TaskStatusSource::SourceExecutor,
            ],
            all_reasons.to_vec(),
        );
        let extra_bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&rkyv_extra).unwrap_or_default();
        type ExtraRkyvTuple = (
            FrameworkInfo,
            AgentInfo,
            Vec<CheckSpec>,
            Vec<CheckStatusInfo>,
            TaskStatusDetails,
            WeightInfo,
            QuotaConfig,
            Vec<TaskStatusSource>,
            Vec<TaskStatusReason>,
        );
        for i in 0..extra_bytes.len() {
            let mut corrupted = extra_bytes.clone();
            for (j, b) in corrupted.iter_mut().enumerate() {
                if i == j {
                    *b ^= 0xFF;
                }
            }
            let _: Result<ExtraRkyvTuple, rkyv::rancor::Error> = rkyv::from_bytes(&corrupted);
        }
        let decoded: Result<ExtraRkyvTuple, rkyv::rancor::Error> = rkyv::from_bytes(&extra_bytes);
        assert!(decoded.is_ok());
    }
}
