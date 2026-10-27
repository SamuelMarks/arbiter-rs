//! Strongly-typed, validated domain identifier newtypes for Arbiter.
//!
//! All identifiers enforce non-empty, bounded-length, URL-safe ASCII invariants upon construction,
//! preventing injection and malformed lookup keys across the control plane.

use core::fmt;
use core::str::FromStr;

use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use serde::{Deserialize, Serialize};

use crate::error::{ArbiterError, ArbiterResult};

/// Maximum permitted length in bytes for standard domain identifiers.
pub const MAX_IDENTIFIER_LEN: usize = 128;

/// Maximum permitted length in bytes for SPIFFE workload identity URIs.
pub const MAX_SPIFFE_URI_LEN: usize = 512;

/// Validates a standard domain identifier string.
///
/// Permitted characters: ASCII alphanumeric (`a-z`, `A-Z`, `0-9`), hyphen (`-`),
/// underscore (`_`), dot (`.`), and colon (`:`).
///
/// # Arguments
///
/// * `kind` - Name of the identifier type for error reporting.
/// * `value` - The candidate string slice to validate.
///
/// # Returns
///
/// `Ok(())` if the string satisfies all invariants.
///
/// # Errors
///
/// Returns [`ArbiterError::EmptyIdentifier`] if `value` is empty, or
/// [`ArbiterError::InvalidIdentifierCharacters`] if `value` exceeds [`MAX_IDENTIFIER_LEN`]
/// or contains disallowed characters.
pub fn validate_identifier(kind: &str, value: &str) -> ArbiterResult<()> {
    if value.is_empty() {
        return Err(ArbiterError::EmptyIdentifier {
            kind: kind.to_owned(),
        });
    }
    if value.len() > MAX_IDENTIFIER_LEN {
        return Err(ArbiterError::InvalidIdentifierCharacters {
            kind: kind.to_owned(),
            value: value.to_owned(),
            reason: format!("exceeds maximum length of {MAX_IDENTIFIER_LEN} bytes"),
        });
    }
    if value.contains("..") {
        return Err(ArbiterError::InvalidIdentifierCharacters {
            kind: kind.to_owned(),
            value: value.to_owned(),
            reason: "contains disallowed path-traversal sequence '..'".to_owned(),
        });
    }
    for byte in value.bytes() {
        let is_valid = byte.is_ascii_alphanumeric()
            || byte == b'-'
            || byte == b'_'
            || byte == b'.'
            || byte == b':';
        if !is_valid {
            return Err(ArbiterError::InvalidIdentifierCharacters {
                kind: kind.to_owned(),
                value: value.to_owned(),
                reason: format!("contains disallowed byte 0x{byte:02x}"),
            });
        }
    }
    Ok(())
}

/// Macro generating a validated string newtype identifier with full trait implementations.
macro_rules! define_string_id {
    ($(#[$meta:meta])* $name:ident, $kind_literal:literal) => {
        $(#[$meta])*
        #[derive(
            Debug,
            Default,
            Clone,
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
        #[rkyv(derive(PartialEq, Eq, PartialOrd, Ord, Hash))]
        pub struct $name(pub(crate) String);

        impl $name {
            /// Creates a new validated identifier from a string slice.
            ///
            /// # Arguments
            ///
            /// * `value` - The candidate identifier string slice.
            ///
            /// # Returns
            ///
            /// A validated instance of `Self`.
            ///
            /// # Errors
            ///
            /// Returns [`ArbiterError::EmptyIdentifier`] or [`ArbiterError::InvalidIdentifierCharacters`]
            /// if validation fails.
            pub fn new(value: &str) -> ArbiterResult<Self> {
                validate_identifier($kind_literal, value)?;
                Ok(Self(value.to_owned()))
            }

            /// Returns the underlying string slice of this identifier.
            ///
            /// # Returns
            ///
            /// The validated string slice `&str`.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            /// Formats the identifier as its underlying string.
            ///
            /// # Arguments
            ///
            /// * `f` - The formatter.
            ///
            /// # Returns
            ///
            /// `fmt::Result` indicating formatting success.
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = ArbiterError;

            /// Parses a string slice into a validated identifier.
            ///
            /// # Arguments
            ///
            /// * `s` - Input string slice.
            ///
            /// # Returns
            ///
            /// A validated identifier.
            ///
            /// # Errors
            ///
            /// Returns [`ArbiterError`] if validation fails.
            fn from_str(s: &str) -> ArbiterResult<Self> {
                Self::new(s)
            }
        }
    };
}

define_string_id!(
    /// Unique identifier for a Master control-plane instance in an Arbiter cluster.
    MasterId,
    "MasterId"
);

define_string_id!(
    /// Unique identifier for a physical or virtual machine host (`MachineID` in Mesos maintenance).
    MachineId,
    "MachineId"
);

define_string_id!(
    /// Unique identifier for an Agent node in an Arbiter cluster.
    AgentId,
    "AgentId"
);

define_string_id!(
    /// Unique identifier for a registered scheduling Framework.
    FrameworkId,
    "FrameworkId"
);

define_string_id!(
    /// Unique identifier for an individual scheduled Task.
    TaskId,
    "TaskId"
);

define_string_id!(
    /// Unique identifier for an atomic Gang / `TaskGroup` workload.
    TaskGroupId,
    "TaskGroupId"
);

define_string_id!(
    /// Unique identifier for a resource Offer sent to a Framework.
    OfferId,
    "OfferId"
);

define_string_id!(
    /// Unique identifier for a Mesos v1 maintenance drain `InverseOffer` sent to a Framework.
    InverseOfferId,
    "InverseOfferId"
);

define_string_id!(
    /// Validated Windows Job Object kernel handle name (`JobObjectHandle`, e.g., `job-task-01`).
    JobObjectHandle,
    "JobObjectHandle"
);

define_string_id!(
    /// Unique identifier for an Executor instance on an Agent.
    ExecutorId,
    "ExecutorId"
);

define_string_id!(
    /// Hierarchical role name used for quota and HDRF fairness accounting.
    RoleName,
    "RoleName"
);

define_string_id!(
    /// Unique identifier for a logical or physical Arbiter cluster.
    ClusterId,
    "ClusterId"
);

define_string_id!(
    /// Unique identifier for a multi-cluster Federation fabric.
    FederationId,
    "FederationId"
);

define_string_id!(
    /// Unique identifier for a time-bounded control-plane or workload Lease.
    LeaseId,
    "LeaseId"
);

define_string_id!(
    /// Unique identifier for a co-located stateful workload Election Group.
    ElectionGroupId,
    "ElectionGroupId"
);

define_string_id!(
    /// Unique identifier for a hardware device (CPU socket, GPU, TPU, NIC, Storage controller).
    DeviceId,
    "DeviceId"
);

define_string_id!(
    /// Unique identifier for a multi-host TPU Pod slice or GPU partition slice.
    SliceId,
    "SliceId"
);

define_string_id!(
    /// Unique identifier for a persistent storage volume or ZFS dataset.
    VolumeId,
    "VolumeId"
);

define_string_id!(
    /// Unique identifier for an encrypted workload secret.
    SecretId,
    "SecretId"
);

define_string_id!(
    /// Unique identifier for a role Quota policy.
    QuotaId,
    "QuotaId"
);

define_string_id!(
    /// Unique identifier for a Mesos v1 Offer Operation (`RESERVE`, `UNRESERVE`, `CREATE`, `DESTROY`, `LAUNCH`).
    OperationId,
    "OperationId"
);

define_string_id!(
    /// Unique identifier for a scheduled Agent Maintenance Window.
    MaintenanceWindowId,
    "MaintenanceWindowId"
);

define_string_id!(
    /// Unique identifier for an at-least-once task or operation status update requiring acknowledgment.
    StatusUpdateUuid,
    "StatusUpdateUuid"
);

define_string_id!(
    /// Unique identifier for a local or external CSI Resource Provider on an Agent.
    ResourceProviderId,
    "ResourceProviderId"
);

define_string_id!(
    /// Fault-domain geographic region identifier (Mesos `DomainInfo::FaultDomain::RegionInfo`).
    RegionName,
    "RegionName"
);

define_string_id!(
    /// Fault-domain availability zone or rack identifier (Mesos `DomainInfo::FaultDomain::ZoneInfo`).
    ZoneName,
    "ZoneName"
);

define_string_id!(
    /// Unique identifier for an OCI container instance (`crun`, `runc`, `containerd`, `ocijail`, `runhcs`).
    ContainerId,
    "ContainerId"
);

impl ContainerId {
    /// Constructs a hierarchical Mesos v1 nested [`ContainerId`] (`<parent>.<child>`).
    ///
    /// # Arguments
    ///
    /// * `parent` - Parent container identifier.
    /// * `child` - Child container identifier (must not already contain `.`).
    ///
    /// # Returns
    ///
    /// Validated nested [`ContainerId`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::InvalidIdentifierCharacters`] if the combined identifier
    /// exceeds [`MAX_IDENTIFIER_LEN`] or `child` is empty/malformed.
    pub fn new_nested(parent: &Self, child: &str) -> ArbiterResult<Self> {
        validate_identifier("ContainerId", child)?;
        let combined = format!("{}.{child}", parent.as_str());
        Self::new(&combined)
    }

    /// Returns the immediate parent [`ContainerId`] if this container is a nested child (`<parent>.<child>`).
    ///
    /// # Returns
    ///
    /// `Some(parent_container_id)` if nested, or `None` if top-level.
    pub fn parent_container_id(&self) -> Option<Self> {
        self.0
            .rsplit_once('.')
            .map(|(parent_str, _)| Self(parent_str.to_owned()))
    }

    /// Returns `true` if this [`ContainerId`] represents a nested child container.
    ///
    /// # Returns
    ///
    /// `true` if `self` has a parent container.
    pub fn is_nested(&self) -> bool {
        self.0.contains('.')
    }
}

define_string_id!(
    /// Unique identifier for a lightweight `MicroVM` instance (`Firecracker`, `bhyve`, `Hyper-V`, `Virtualization.framework`).
    VmId,
    "VmId"
);

define_string_id!(
    /// Validated Linux `cgroup v2` relative hierarchy identifier.
    CgroupPath,
    "CgroupPath"
);

define_string_id!(
    /// Validated Mesos v1 framework or operator authentication principal name (`PrincipalName`).
    PrincipalName,
    "PrincipalName"
);

define_string_id!(
    /// Validated container network namespace handle (`NetNsHandle`, e.g., `netns-ctr-01`).
    NetNsHandle,
    "NetNsHandle"
);

define_string_id!(
    /// Validated Mesos v1 HTTP/2 `RecordIO` and QUIC subscription stream identifier (`Mesos-Stream-Id`).
    StreamId,
    "StreamId"
);

define_string_id!(
    /// Unique UUID identifier for Mesos v1 `Offer::Operation` status tracking and reconciliation (`OperationUuid`).
    OperationUuid,
    "OperationUuid"
);

define_string_id!(
    /// Unique identifier for a Mesos v1 `OfferFilter` (`RefuseSeconds`) entry (`OfferFilterId`).
    OfferFilterId,
    "OfferFilterId"
);

/// Validated ZFS pool and dataset path (e.g., `tank/arbiter/vol-01`).
#[derive(
    Debug,
    Default,
    Clone,
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
pub struct ZfsDatasetName(String);

impl ZfsDatasetName {
    /// Validates and constructs a [`ZfsDatasetName`].
    ///
    /// Must be non-empty, not start or end with `/`, not contain `..` or `//`, and only contain
    /// ASCII alphanumeric characters, `-`, `_`, `.`, `:`, or `/`.
    ///
    /// # Arguments
    ///
    /// * `dataset` - Candidate ZFS dataset path string slice.
    ///
    /// # Returns
    ///
    /// Validated [`ZfsDatasetName`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::EmptyIdentifier`] if `dataset` is empty, or
    /// [`ArbiterError::InvalidIdentifierCharacters`] if malformed.
    pub fn new(dataset: &str) -> ArbiterResult<Self> {
        if dataset.is_empty() {
            return Err(ArbiterError::EmptyIdentifier {
                kind: "ZfsDatasetName".to_owned(),
            });
        }
        if dataset.starts_with('/')
            || dataset.ends_with('/')
            || dataset.contains("//")
            || dataset.contains("..")
        {
            return Err(ArbiterError::InvalidIdentifierCharacters {
                kind: "ZfsDatasetName".to_owned(),
                value: dataset.to_owned(),
                reason: "ZFS dataset name must not start/end with '/', contain '//', or '..'"
                    .to_owned(),
            });
        }
        let chars_ok = dataset.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || b == b'-'
                || b == b'_'
                || b == b'.'
                || b == b':'
                || b == b'/'
        });
        if !chars_ok {
            return Err(ArbiterError::InvalidIdentifierCharacters {
                kind: "ZfsDatasetName".to_owned(),
                value: dataset.to_owned(),
                reason: "ZFS dataset name contains disallowed characters".to_owned(),
            });
        }
        Ok(Self(dataset.to_owned()))
    }

    /// Returns the ZFS dataset name string slice.
    ///
    /// # Returns
    ///
    /// Dataset name `&str`.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ZfsDatasetName {
    /// Formats the ZFS dataset name.
    ///
    /// # Arguments
    ///
    /// * `f` - The formatter.
    ///
    /// # Returns
    ///
    /// `fmt::Result`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for ZfsDatasetName {
    type Err = ArbiterError;

    /// Parses a string slice into a [`ZfsDatasetName`].
    ///
    /// # Arguments
    ///
    /// * `s` - Candidate dataset path string slice.
    ///
    /// # Returns
    ///
    /// Validated [`ZfsDatasetName`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError`] if validation fails.
    fn from_str(s: &str) -> ArbiterResult<Self> {
        Self::new(s)
    }
}

/// Validated OCI container image reference (`[registry/]repository[:tag][@sha256:digest]`).
#[derive(
    Debug,
    Default,
    Clone,
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
pub struct OciImageReference {
    /// Full canonical OCI image reference string.
    raw: String,
    /// Repository path (including optional registry prefix).
    repository: String,
    /// Optional image tag (e.g., `"latest"` or `"v1.2.3"`).
    tag: Option<String>,
    /// Optional immutable SHA-256 content digest.
    digest: Option<Sha256Digest>,
}

impl OciImageReference {
    /// Parses and validates an [`OciImageReference`] string (`[registry/]repo[:tag][@sha256:hex]`).
    ///
    /// # Arguments
    ///
    /// * `reference` - Candidate OCI image reference string slice.
    ///
    /// # Returns
    ///
    /// Validated [`OciImageReference`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::EmptyIdentifier`] if `reference` is empty, or
    /// [`ArbiterError::InvalidIdentifierCharacters`] if the repository, tag, or digest is malformed.
    pub fn new(reference: &str) -> ArbiterResult<Self> {
        if reference.is_empty() {
            return Err(ArbiterError::EmptyIdentifier {
                kind: "OciImageReference".to_owned(),
            });
        }
        if reference
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
        {
            return Err(ArbiterError::InvalidIdentifierCharacters {
                kind: "OciImageReference".to_owned(),
                value: reference.to_owned(),
                reason: "OCI image reference must not contain whitespace or control characters"
                    .to_owned(),
            });
        }
        let (before_digest, digest) = if let Some((repo_tag, dig_part)) = reference.split_once('@')
        {
            let Some(hex_str) = dig_part.strip_prefix("sha256:") else {
                return Err(ArbiterError::InvalidIdentifierCharacters {
                    kind: "OciImageReference".to_owned(),
                    value: reference.to_owned(),
                    reason: "OCI image digest must start with 'sha256:'".to_owned(),
                });
            };
            (repo_tag, Some(Sha256Digest::new(hex_str)?))
        } else {
            (reference, None)
        };
        let last_slash = before_digest.rfind('/');
        let last_colon = before_digest.rfind(':');
        let (repository, tag) = match (last_slash, last_colon) {
            (Some(slash_idx), Some(colon_idx)) if colon_idx > slash_idx => (
                &before_digest[..colon_idx],
                Some(&before_digest[colon_idx + 1..]),
            ),
            (None, Some(colon_idx)) => (
                &before_digest[..colon_idx],
                Some(&before_digest[colon_idx + 1..]),
            ),
            _ => (before_digest, None),
        };
        if repository.is_empty() || repository.starts_with('/') || repository.ends_with('/') {
            return Err(ArbiterError::InvalidIdentifierCharacters {
                kind: "OciImageReference".to_owned(),
                value: reference.to_owned(),
                reason: "OCI repository path must be non-empty and not start/end with '/'"
                    .to_owned(),
            });
        }
        if let Some(t) = tag
            && t.is_empty()
        {
            return Err(ArbiterError::InvalidIdentifierCharacters {
                kind: "OciImageReference".to_owned(),
                value: reference.to_owned(),
                reason: "OCI image tag after ':' cannot be empty".to_owned(),
            });
        }
        Ok(Self {
            raw: reference.to_owned(),
            repository: repository.to_owned(),
            tag: tag.map(ToOwned::to_owned),
            digest,
        })
    }

    /// Returns the full OCI image reference string slice.
    ///
    /// # Returns
    ///
    /// Full image reference `&str`.
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    /// Returns the repository component (including registry host if present).
    ///
    /// # Returns
    ///
    /// Repository `&str`.
    pub fn repository(&self) -> &str {
        &self.repository
    }

    /// Returns the optional image tag.
    ///
    /// # Returns
    ///
    /// `Some(&str)` if a tag was specified, otherwise `None`.
    pub fn tag(&self) -> Option<&str> {
        self.tag.as_deref()
    }

    /// Returns the optional immutable SHA-256 content digest.
    ///
    /// # Returns
    ///
    /// `Some(&Sha256Digest)` if `@sha256:...` was specified, otherwise `None`.
    pub const fn digest(&self) -> Option<&Sha256Digest> {
        self.digest.as_ref()
    }
}

impl fmt::Display for OciImageReference {
    /// Formats the OCI image reference.
    ///
    /// # Arguments
    ///
    /// * `f` - The formatter.
    ///
    /// # Returns
    ///
    /// `fmt::Result`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

impl FromStr for OciImageReference {
    type Err = ArbiterError;

    /// Parses a string slice into an [`OciImageReference`].
    ///
    /// # Arguments
    ///
    /// * `s` - Candidate OCI image reference string slice.
    ///
    /// # Returns
    ///
    /// Validated [`OciImageReference`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError`] if validation fails.
    fn from_str(s: &str) -> ArbiterResult<Self> {
        Self::new(s)
    }
}

/// Strongly-typed POSIX / OS signal number (`1..=64`).
#[must_use]
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
pub struct SignalNumber(i32);

impl Default for SignalNumber {
    /// Returns `SIGTERM` (`15`) as the default graceful termination [`SignalNumber`].
    ///
    /// # Returns
    ///
    /// `SignalNumber(15)`.
    fn default() -> Self {
        Self::SIGTERM
    }
}

impl SignalNumber {
    /// POSIX `SIGINT` (`2`) interrupt signal.
    pub const SIGINT: Self = Self(2);
    /// POSIX `SIGKILL` (`9`) unconditional termination signal.
    pub const SIGKILL: Self = Self(9);
    /// POSIX `SIGTERM` (`15`) graceful termination signal.
    pub const SIGTERM: Self = Self(15);
    /// POSIX `SIGSTOP` (`19`) process pause signal.
    pub const SIGSTOP: Self = Self(19);
    /// POSIX `SIGCONT` (`18`) process resume signal.
    pub const SIGCONT: Self = Self(18);

    /// Validates and constructs a [`SignalNumber`] in `1..=64`.
    ///
    /// # Arguments
    ///
    /// * `signum` - Numeric signal identifier (`1..=64`).
    ///
    /// # Returns
    ///
    /// Validated [`SignalNumber`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::InvalidResourceQuantity`] if `signum` is outside `1..=64`.
    pub fn new(signum: i32) -> ArbiterResult<Self> {
        if !(1..=64).contains(&signum) {
            return Err(ArbiterError::InvalidResourceQuantity {
                resource: "SignalNumber".to_owned(),
                quantity: 0,
                reason: format!("signal number {signum} must be in 1..=64"),
            });
        }
        Ok(Self(signum))
    }

    /// Returns the raw `i32` signal number.
    ///
    /// # Returns
    ///
    /// Raw `i32` signal number.
    pub const fn get(self) -> i32 {
        self.0
    }
}

impl fmt::Display for SignalNumber {
    /// Formats the signal number.
    ///
    /// # Arguments
    ///
    /// * `f` - The formatter.
    ///
    /// # Returns
    ///
    /// `fmt::Result`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Validated `PCIe` Bus:Device.Function (`BDF`) address (`DDDD:BB:DD.F`, e.g., `0000:c1:00.0`).
#[derive(
    Debug,
    Default,
    Clone,
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
pub struct PcieBdfAddress(String);

impl PcieBdfAddress {
    /// Exact character length (`12`) of a canonical `DDDD:BB:DD.F` `PCIe` BDF address.
    pub const BDF_LEN: usize = 12;

    /// Validates and constructs a canonical lowercase [`PcieBdfAddress`] (`DDDD:BB:DD.F`).
    ///
    /// # Arguments
    ///
    /// * `bdf` - Candidate `PCIe` BDF address string (e.g., `"0000:c1:00.0"`).
    ///
    /// # Returns
    ///
    /// Validated lowercase [`PcieBdfAddress`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::InvalidIdentifierCharacters`] if `bdf` is not in `DDDD:BB:DD.F`
    /// hexadecimal format with function `F` in `'0'..='7'`.
    pub fn new(bdf: &str) -> ArbiterResult<Self> {
        if bdf.len() != Self::BDF_LEN {
            return Err(ArbiterError::InvalidIdentifierCharacters {
                kind: "PcieBdfAddress".to_owned(),
                value: bdf.to_owned(),
                reason: "PCIe BDF address must be 12 characters in 'DDDD:BB:DD.F' format"
                    .to_owned(),
            });
        }
        let bytes = bdf.as_bytes();
        let colons_and_dot_ok = bytes.get(4) == Some(&b':')
            && bytes.get(7) == Some(&b':')
            && bytes.get(10) == Some(&b'.');
        let hex_positions = [0_usize, 1, 2, 3, 5, 6, 8, 9];
        let hex_ok = hex_positions.iter().all(|&idx| {
            bytes
                .get(idx)
                .copied()
                .is_some_and(|b| b.is_ascii_hexdigit())
        });
        let func_ok = bytes
            .get(11)
            .copied()
            .is_some_and(|b| (b'0'..=b'7').contains(&b));
        if !colons_and_dot_ok || !hex_ok || !func_ok {
            return Err(ArbiterError::InvalidIdentifierCharacters {
                kind: "PcieBdfAddress".to_owned(),
                value: bdf.to_owned(),
                reason: "invalid PCIe BDF syntax (expected hex DDDD:BB:DD.F with F in 0..=7)"
                    .to_owned(),
            });
        }
        Ok(Self(bdf.to_ascii_lowercase()))
    }

    /// Returns the canonical `DDDD:BB:DD.F` string slice.
    ///
    /// # Returns
    ///
    /// Canonical `&str`.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PcieBdfAddress {
    /// Formats the `PCIe` BDF address.
    ///
    /// # Arguments
    ///
    /// * `f` - The formatter.
    ///
    /// # Returns
    ///
    /// `fmt::Result`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for PcieBdfAddress {
    type Err = ArbiterError;

    /// Parses a string slice into a [`PcieBdfAddress`].
    ///
    /// # Arguments
    ///
    /// * `s` - Candidate BDF string slice.
    ///
    /// # Returns
    ///
    /// Validated [`PcieBdfAddress`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::InvalidIdentifierCharacters`] if malformed.
    fn from_str(s: &str) -> ArbiterResult<Self> {
        Self::new(s)
    }
}

/// Validated FreeBSD Jail numeric identifier (`jid >= 1`).
#[must_use]
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
pub struct JailId(i32);

impl Default for JailId {
    /// Returns the default valid [`JailId`] (`1`).
    ///
    /// # Returns
    ///
    /// `JailId(1)`.
    fn default() -> Self {
        Self(1)
    }
}

impl JailId {
    /// Constructs a validated FreeBSD [`JailId`] (`>= 1`).
    ///
    /// # Arguments
    ///
    /// * `jid` - Raw FreeBSD jail identifier (`>= 1`).
    ///
    /// # Returns
    ///
    /// Validated [`JailId`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::InvalidResourceQuantity`] if `jid <= 0`.
    pub fn new(jid: i32) -> ArbiterResult<Self> {
        if jid <= 0 {
            return Err(ArbiterError::InvalidResourceQuantity {
                resource: "JailId".to_owned(),
                quantity: 0,
                reason: "FreeBSD jail ID must be >= 1".to_owned(),
            });
        }
        Ok(Self(jid))
    }

    /// Returns the underlying `i32` jail identifier.
    ///
    /// # Returns
    ///
    /// Raw `i32` jail ID.
    pub const fn get(self) -> i32 {
        self.0
    }
}

impl fmt::Display for JailId {
    /// Formats the FreeBSD jail ID.
    ///
    /// # Arguments
    ///
    /// * `f` - The formatter.
    ///
    /// # Returns
    ///
    /// `fmt::Result`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Validated illumos Zone numeric identifier (`zoneid >= 1` for non-global zones).
#[must_use]
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
pub struct ZoneId(i32);

impl Default for ZoneId {
    /// Returns the default valid non-global [`ZoneId`] (`1`).
    ///
    /// # Returns
    ///
    /// `ZoneId(1)`.
    fn default() -> Self {
        Self(1)
    }
}

impl ZoneId {
    /// Constructs a validated illumos non-global [`ZoneId`] (`>= 1`).
    ///
    /// # Arguments
    ///
    /// * `zid` - Raw illumos zone identifier (`>= 1`).
    ///
    /// # Returns
    ///
    /// Validated [`ZoneId`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::InvalidResourceQuantity`] if `zid <= 0`.
    pub fn new(zid: i32) -> ArbiterResult<Self> {
        if zid <= 0 {
            return Err(ArbiterError::InvalidResourceQuantity {
                resource: "ZoneId".to_owned(),
                quantity: 0,
                reason: "illumos non-global zone ID must be >= 1".to_owned(),
            });
        }
        Ok(Self(zid))
    }

    /// Returns the underlying `i32` zone identifier.
    ///
    /// # Returns
    ///
    /// Raw `i32` zone ID.
    pub const fn get(self) -> i32 {
        self.0
    }
}

impl fmt::Display for ZoneId {
    /// Formats the illumos zone ID.
    ///
    /// # Arguments
    ///
    /// * `f` - The formatter.
    ///
    /// # Returns
    ///
    /// `fmt::Result`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Validated network or local IPC socket endpoint (`host:port` or Unix Domain Socket / Named Pipe path).
#[derive(
    Debug,
    Default,
    Clone,
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
pub struct SocketEndpoint(String);

impl SocketEndpoint {
    /// Validates and constructs a [`SocketEndpoint`].
    ///
    /// Accepts either a `host:port` TCP/UDP address (with port in `1..=65535`) or a non-empty
    /// Unix Domain Socket (`/path/to.sock`) / Windows Named Pipe (`\\.\pipe\name`) path without null bytes.
    ///
    /// # Arguments
    ///
    /// * `endpoint` - Candidate endpoint string slice.
    ///
    /// # Returns
    ///
    /// Validated [`SocketEndpoint`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::EmptyIdentifier`] if `endpoint` is empty, or
    /// [`ArbiterError::InvalidIdentifierCharacters`] if malformed.
    pub fn new(endpoint: &str) -> ArbiterResult<Self> {
        if endpoint.is_empty() {
            return Err(ArbiterError::EmptyIdentifier {
                kind: "SocketEndpoint".to_owned(),
            });
        }
        if endpoint.contains('\0') {
            return Err(ArbiterError::InvalidIdentifierCharacters {
                kind: "SocketEndpoint".to_owned(),
                value: endpoint.to_owned(),
                reason: "endpoint must not contain null bytes".to_owned(),
            });
        }
        if endpoint.starts_with('/') || endpoint.starts_with(r"\\.\pipe\") {
            if endpoint.len() <= 1 || endpoint == r"\\.\pipe\" {
                return Err(ArbiterError::InvalidIdentifierCharacters {
                    kind: "SocketEndpoint".to_owned(),
                    value: endpoint.to_owned(),
                    reason: "IPC socket path must include a filename".to_owned(),
                });
            }
            return Ok(Self(endpoint.to_owned()));
        }
        let Some((host, port_str)) = endpoint.rsplit_once(':') else {
            return Err(ArbiterError::InvalidIdentifierCharacters {
                kind: "SocketEndpoint".to_owned(),
                value: endpoint.to_owned(),
                reason: "network endpoint must be in 'host:port' format or start with '/'"
                    .to_owned(),
            });
        };
        if host.is_empty() {
            return Err(ArbiterError::InvalidIdentifierCharacters {
                kind: "SocketEndpoint".to_owned(),
                value: endpoint.to_owned(),
                reason: "host portion of endpoint cannot be empty".to_owned(),
            });
        }
        let port =
            port_str
                .parse::<u16>()
                .map_err(|_| ArbiterError::InvalidIdentifierCharacters {
                    kind: "SocketEndpoint".to_owned(),
                    value: endpoint.to_owned(),
                    reason: "port must be an integer in 1..=65535".to_owned(),
                })?;
        if port == 0 {
            return Err(ArbiterError::InvalidResourceQuantity {
                resource: "SocketEndpoint::port".to_owned(),
                quantity: 0,
                reason: "port number must be non-zero".to_owned(),
            });
        }
        Ok(Self(endpoint.to_owned()))
    }

    /// Returns the underlying endpoint string slice.
    ///
    /// # Returns
    ///
    /// Endpoint `&str`.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns `true` if this endpoint refers to a local Unix Domain Socket or Windows Named Pipe.
    ///
    /// # Returns
    ///
    /// `true` if local IPC path.
    pub fn is_local_ipc(&self) -> bool {
        self.0.starts_with('/') || self.0.starts_with(r"\\.\pipe\")
    }
}

impl fmt::Display for SocketEndpoint {
    /// Formats the socket endpoint string.
    ///
    /// # Arguments
    ///
    /// * `f` - The formatter.
    ///
    /// # Returns
    ///
    /// `fmt::Result`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Validated 64-character lowercase hexadecimal SHA-256 content digest.
#[derive(
    Debug,
    Default,
    Clone,
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
pub struct Sha256Digest(String);

impl Sha256Digest {
    /// Exact length of a hex-encoded SHA-256 digest (`64` ASCII hex characters).
    pub const HEX_LEN: usize = 64;

    /// Validates and constructs a [`Sha256Digest`] from a 64-character hexadecimal string,
    /// normalizing uppercase hex digits to canonical lowercase.
    ///
    /// # Arguments
    ///
    /// * `hex_str` - Candidate 64-character hex string.
    ///
    /// # Returns
    ///
    /// Validated lowercase [`Sha256Digest`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::InvalidIdentifierCharacters`] if `hex_str` is not exactly 64 hex characters.
    pub fn new(hex_str: &str) -> ArbiterResult<Self> {
        if hex_str.len() != Self::HEX_LEN {
            return Err(ArbiterError::InvalidIdentifierCharacters {
                kind: "Sha256Digest".to_owned(),
                value: hex_str.to_owned(),
                reason: format!(
                    "SHA-256 hex digest must be exactly {} characters",
                    Self::HEX_LEN
                ),
            });
        }
        if !hex_str.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(ArbiterError::InvalidIdentifierCharacters {
                kind: "Sha256Digest".to_owned(),
                value: hex_str.to_owned(),
                reason: "contains non-hexadecimal character".to_owned(),
            });
        }
        Ok(Self(hex_str.to_ascii_lowercase()))
    }

    /// Returns the canonical 64-character lowercase hex digest string slice.
    ///
    /// # Returns
    ///
    /// Hex string slice `&str`.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Sha256Digest {
    /// Formats the SHA-256 hex digest.
    ///
    /// # Arguments
    ///
    /// * `f` - The formatter.
    ///
    /// # Returns
    ///
    /// `fmt::Result`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Validated relative sandbox path that rejects path traversal (`..`), leading slashes (`/`),
/// backslashes (`\`), and null bytes at construction time.
#[derive(
    Debug,
    Default,
    Clone,
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
pub struct SandboxPath(String);

impl SandboxPath {
    /// Validates and constructs a safe relative [`SandboxPath`].
    ///
    /// # Arguments
    ///
    /// * `rel_path` - Candidate relative path inside a task sandbox.
    ///
    /// # Returns
    ///
    /// Validated [`SandboxPath`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::EmptyIdentifier`] if `rel_path` is empty, or
    /// [`ArbiterError::SandboxError`] if `rel_path` starts with `/`, contains `\`, `\0`, or `..` segments.
    pub fn new(rel_path: &str) -> ArbiterResult<Self> {
        if rel_path.is_empty() {
            return Err(ArbiterError::EmptyIdentifier {
                kind: "SandboxPath".to_owned(),
            });
        }
        if rel_path.starts_with('/') || rel_path.contains('\\') || rel_path.contains('\0') {
            return Err(ArbiterError::SandboxError {
                mechanism: "SandboxPath".to_owned(),
                reason: format!(
                    "disallowed absolute, backslash, or null character in '{rel_path}'"
                ),
            });
        }
        let mut normalized_parts = Vec::new();
        for seg in rel_path.split('/') {
            if seg.is_empty() || seg == "." {
                continue;
            }
            if seg == ".." {
                return Err(ArbiterError::SandboxError {
                    mechanism: "SandboxPath".to_owned(),
                    reason: format!("path traversal '..' rejected in '{rel_path}'"),
                });
            }
            normalized_parts.push(seg);
        }
        if normalized_parts.is_empty() {
            return Err(ArbiterError::EmptyIdentifier {
                kind: "SandboxPath".to_owned(),
            });
        }
        Ok(Self(normalized_parts.join("/")))
    }

    /// Returns the normalized relative path string slice.
    ///
    /// # Returns
    ///
    /// Relative path `&str`.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SandboxPath {
    /// Formats the relative sandbox path.
    ///
    /// # Arguments
    ///
    /// * `f` - The formatter.
    ///
    /// # Returns
    ///
    /// `fmt::Result`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Strongly-typed non-zero operating system process identifier (`PID`).
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
pub struct OsProcessId(u32);

impl Default for OsProcessId {
    /// Returns PID `1` as the default valid [`OsProcessId`].
    ///
    /// # Returns
    ///
    /// `OsProcessId(1)`.
    fn default() -> Self {
        Self(1)
    }
}

impl OsProcessId {
    /// Constructs a validated non-zero [`OsProcessId`].
    ///
    /// # Arguments
    ///
    /// * `pid` - Raw OS process ID (`>= 1`).
    ///
    /// # Returns
    ///
    /// Validated [`OsProcessId`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::InvalidResourceQuantity`] if `pid == 0`.
    pub fn new(pid: u32) -> ArbiterResult<Self> {
        if pid == 0 {
            return Err(ArbiterError::InvalidResourceQuantity {
                resource: "OsProcessId".to_owned(),
                quantity: 0,
                reason: "process ID must be non-zero".to_owned(),
            });
        }
        Ok(Self(pid))
    }

    /// Returns the raw `u32` process identifier.
    ///
    /// # Returns
    ///
    /// Raw `u32` PID.
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl fmt::Display for OsProcessId {
    /// Formats the OS PID.
    ///
    /// # Arguments
    ///
    /// * `f` - The formatter.
    ///
    /// # Returns
    ///
    /// `fmt::Result`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Canonical type alias for [`OsProcessId`].
pub type ProcessId = OsProcessId;

/// Strongly-typed non-negative POSIX file descriptor identifier (`fd >= 0`).
#[derive(
    Debug,
    Default,
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
pub struct FileDescriptorId(i32);

impl FileDescriptorId {
    /// Constructs a validated non-negative [`FileDescriptorId`].
    ///
    /// # Arguments
    ///
    /// * `fd` - Raw OS file descriptor (`>= 0`).
    ///
    /// # Returns
    ///
    /// Validated [`FileDescriptorId`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::InvalidResourceQuantity`] if `fd < 0`.
    pub fn new(fd: i32) -> ArbiterResult<Self> {
        if fd < 0 {
            return Err(ArbiterError::InvalidResourceQuantity {
                resource: "FileDescriptorId".to_owned(),
                quantity: 0,
                reason: "file descriptor must be non-negative (>= 0)".to_owned(),
            });
        }
        Ok(Self(fd))
    }

    /// Returns the raw `i32` file descriptor number.
    ///
    /// # Returns
    ///
    /// Raw `i32` descriptor.
    pub const fn get(self) -> i32 {
        self.0
    }
}

impl fmt::Display for FileDescriptorId {
    /// Formats the file descriptor number.
    ///
    /// # Arguments
    ///
    /// * `f` - The formatter.
    ///
    /// # Returns
    ///
    /// `fmt::Result`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Strongly-typed process exit code with POSIX signal-termination decoding (`128 + signum`).
#[derive(
    Debug,
    Default,
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
pub struct ExitCode(i32);

impl ExitCode {
    /// Canonical clean exit code (`0`).
    pub const SUCCESS: Self = Self(0);

    /// Wraps a raw process exit status code.
    ///
    /// # Arguments
    ///
    /// * `code` - Raw process exit code (`0` = success, `128 + sig` = signal termination).
    ///
    /// # Returns
    ///
    /// [`ExitCode`].
    pub const fn new(code: i32) -> Self {
        Self(code)
    }

    /// Returns the raw `i32` exit status code.
    ///
    /// # Returns
    ///
    /// Raw `i32` code.
    pub const fn get(self) -> i32 {
        self.0
    }

    /// Returns `true` if the process exited cleanly (`code == 0`).
    ///
    /// # Returns
    ///
    /// `true` if `0`.
    pub const fn is_success(self) -> bool {
        self.0 == 0
    }

    /// If the exit code follows the POSIX `128 + signal` convention (`129..=192`), returns the signal number.
    ///
    /// # Returns
    ///
    /// `Some(signal_number)` if terminated by a signal in `1..=64`, otherwise `None`.
    pub const fn terminating_signal(self) -> Option<i32> {
        if self.0 > 128 && self.0 <= 192 {
            Some(self.0 - 128)
        } else {
            None
        }
    }
}

impl fmt::Display for ExitCode {
    /// Formats the process exit code.
    ///
    /// # Arguments
    ///
    /// * `f` - The formatter.
    ///
    /// # Returns
    ///
    /// `fmt::Result`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Strictly monotonic 64-bit fencing token issued during leader/primary elections.
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
pub struct FencingToken(u64);

impl Default for FencingToken {
    /// Returns the initial valid [`FencingToken`] at epoch `1`.
    ///
    /// # Returns
    ///
    /// `FencingToken(1)`.
    fn default() -> Self {
        Self(1)
    }
}

impl FencingToken {
    /// Creates a new [`FencingToken`] from a raw epoch/index value.
    ///
    /// # Arguments
    ///
    /// * `epoch` - The 64-bit fencing epoch (must be `>= 1`).
    ///
    /// # Returns
    ///
    /// A validated [`FencingToken`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::InvalidResourceQuantity`] if `epoch == 0`.
    pub fn new(epoch: u64) -> ArbiterResult<Self> {
        if epoch == 0 {
            return Err(ArbiterError::InvalidResourceQuantity {
                resource: "FencingToken".to_owned(),
                quantity: 0,
                reason: "fencing token epoch must be non-zero".to_owned(),
            });
        }
        Ok(Self(epoch))
    }

    /// Returns the raw 64-bit integer value of the fencing token.
    ///
    /// # Returns
    ///
    /// The `u64` epoch value.
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Advances the fencing token by 1 using checked addition.
    ///
    /// # Returns
    ///
    /// The next sequential [`FencingToken`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::ArithmeticOverflow`] if the token is at `u64::MAX`.
    pub fn next(self) -> ArbiterResult<Self> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or_else(|| ArbiterError::ArithmeticOverflow {
                operation: "FencingToken::next".to_owned(),
            })
    }

    /// Validates that `self` is at least as new as `minimum_active`.
    ///
    /// # Arguments
    ///
    /// * `minimum_active` - The current active fencing token on the resource/group.
    ///
    /// # Returns
    ///
    /// `Ok(())` if `self >= minimum_active`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::FencingTokenStale`] if `self < minimum_active`.
    pub fn validate_against(self, minimum_active: Self) -> ArbiterResult<()> {
        if self.0 < minimum_active.0 {
            return Err(ArbiterError::FencingTokenStale {
                presented_token: self.0,
                current_token: minimum_active.0,
            });
        }
        Ok(())
    }
}

impl fmt::Display for FencingToken {
    /// Formats the fencing token as its integer epoch.
    ///
    /// # Arguments
    ///
    /// * `f` - The formatter.
    ///
    /// # Returns
    ///
    /// `fmt::Result`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for FencingToken {
    type Err = ArbiterError;

    /// Parses a base-10 integer string into a [`FencingToken`].
    ///
    /// # Arguments
    ///
    /// * `s` - String slice to parse.
    ///
    /// # Returns
    ///
    /// A validated [`FencingToken`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::InvalidIdentifierCharacters`] if not a valid `u64`,
    /// or [`ArbiterError::InvalidResourceQuantity`] if `0`.
    fn from_str(s: &str) -> ArbiterResult<Self> {
        let parsed = s
            .parse::<u64>()
            .map_err(|_| ArbiterError::InvalidIdentifierCharacters {
                kind: "FencingToken".to_owned(),
                value: s.to_owned(),
                reason: "must be an unsigned 64-bit integer".to_owned(),
            })?;
        Self::new(parsed)
    }
}

/// Validated SPIFFE workload identity URI (`spiffe://<trust-domain>/<workload-path>`).
#[derive(
    Debug,
    Default,
    Clone,
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
pub struct SpiffeId {
    /// Full canonical SPIFFE URI.
    uri: String,
    /// Extracted trust domain.
    trust_domain: String,
    /// Extracted workload path (beginning with `/`).
    path: String,
}

impl SpiffeId {
    /// Parses and validates a SPIFFE ID URI string.
    ///
    /// Must start with `spiffe://`, contain a non-empty ASCII trust domain and a non-empty
    /// path starting with `/`, and not exceed [`MAX_SPIFFE_URI_LEN`].
    ///
    /// # Arguments
    ///
    /// * `uri` - Candidate SPIFFE URI string slice.
    ///
    /// # Returns
    ///
    /// A validated [`SpiffeId`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SpiffeIdentityInvalid`] if the URI violates SPIFFE specifications.
    pub fn new(uri: &str) -> ArbiterResult<Self> {
        if uri.len() > MAX_SPIFFE_URI_LEN {
            return Err(ArbiterError::SpiffeIdentityInvalid {
                uri: uri.to_owned(),
                reason: format!("exceeds maximum length of {MAX_SPIFFE_URI_LEN} bytes"),
            });
        }
        let Some(rest) = uri.strip_prefix("spiffe://") else {
            return Err(ArbiterError::SpiffeIdentityInvalid {
                uri: uri.to_owned(),
                reason: "must start with 'spiffe://'".to_owned(),
            });
        };
        let Some((domain, path_part)) = rest.split_once('/') else {
            return Err(ArbiterError::SpiffeIdentityInvalid {
                uri: uri.to_owned(),
                reason: "must contain a trust domain followed by a '/' path".to_owned(),
            });
        };
        if domain.is_empty() || path_part.is_empty() {
            return Err(ArbiterError::SpiffeIdentityInvalid {
                uri: uri.to_owned(),
                reason: "trust domain and workload path must both be non-empty".to_owned(),
            });
        }
        for byte in uri.bytes() {
            let valid = byte.is_ascii_alphanumeric()
                || byte == b'-'
                || byte == b'_'
                || byte == b'.'
                || byte == b':'
                || byte == b'/';
            if !valid {
                return Err(ArbiterError::SpiffeIdentityInvalid {
                    uri: uri.to_owned(),
                    reason: format!("contains disallowed byte 0x{byte:02x}"),
                });
            }
        }
        let trust_domain = domain.to_owned();
        let path = format!("/{path_part}");
        Ok(Self {
            uri: uri.to_owned(),
            trust_domain,
            path,
        })
    }

    /// Returns the full canonical SPIFFE URI string slice.
    ///
    /// # Returns
    ///
    /// The full URI `&str`.
    pub fn as_str(&self) -> &str {
        &self.uri
    }

    /// Returns the trust domain portion of the SPIFFE ID.
    ///
    /// # Returns
    ///
    /// The trust domain `&str`.
    pub fn trust_domain(&self) -> &str {
        &self.trust_domain
    }

    /// Returns the workload path portion of the SPIFFE ID (prefixed with `/`).
    ///
    /// # Returns
    ///
    /// The workload path `&str`.
    pub fn path(&self) -> &str {
        &self.path
    }
}

impl fmt::Display for SpiffeId {
    /// Formats the SPIFFE ID as its canonical URI.
    ///
    /// # Arguments
    ///
    /// * `f` - The formatter.
    ///
    /// # Returns
    ///
    /// `fmt::Result`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.uri)
    }
}

impl FromStr for SpiffeId {
    type Err = ArbiterError;

    /// Parses a string slice into a [`SpiffeId`].
    ///
    /// # Arguments
    ///
    /// * `s` - Candidate URI string slice.
    ///
    /// # Returns
    ///
    /// A validated [`SpiffeId`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SpiffeIdentityInvalid`] on invalid syntax.
    fn from_str(s: &str) -> ArbiterResult<Self> {
        Self::new(s)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    macro_rules! check_id_type {
        ($fn_name:ident, $t:ident, $val:literal) => {
            #[test]
            fn $fn_name() {
                let id = $t::from_str($val);
                assert!(id.is_ok());
                let instance = $t::new($val);
                assert_eq!(id, instance);
                let direct = $t(String::from($val));
                assert_eq!(direct.as_str(), $val);
                assert_eq!(direct.to_string(), $val);
                assert!($t::new("").is_err());
            }
        };
    }

    check_id_type!(test_master_id, MasterId, "master-01.prod:5050");
    check_id_type!(test_machine_id, MachineId, "machine-rack-01:node-02");
    check_id_type!(test_agent_id, AgentId, "agent-01.prod:rack_1");
    check_id_type!(test_framework_id, FrameworkId, "fw-1");
    check_id_type!(test_task_id, TaskId, "task-1");
    check_id_type!(test_task_group_id, TaskGroupId, "tg-1");
    check_id_type!(test_offer_id, OfferId, "offer-1");
    check_id_type!(test_inverse_offer_id, InverseOfferId, "inv-offer-1");
    check_id_type!(test_job_object_handle, JobObjectHandle, "job-win-01");
    check_id_type!(test_executor_id, ExecutorId, "exec-1");
    check_id_type!(test_role_name, RoleName, "role.prod");
    check_id_type!(test_cluster_id, ClusterId, "cluster-a");
    check_id_type!(test_federation_id, FederationId, "fed-global");
    check_id_type!(test_lease_id, LeaseId, "lease-1");
    check_id_type!(test_election_group_id, ElectionGroupId, "pg-primary");
    check_id_type!(test_device_id, DeviceId, "gpu:0");
    check_id_type!(test_slice_id, SliceId, "slice-v5p-0");
    check_id_type!(test_volume_id, VolumeId, "vol-zfs-1");
    check_id_type!(test_secret_id, SecretId, "sec-jwt-1");
    check_id_type!(test_quota_id, QuotaId, "quota-prod");
    check_id_type!(test_operation_id, OperationId, "op-res-1");
    check_id_type!(
        test_maintenance_window_id,
        MaintenanceWindowId,
        "mw-rack-01"
    );
    check_id_type!(test_status_update_uuid, StatusUpdateUuid, "uuid-status-1");
    check_id_type!(test_resource_provider_id, ResourceProviderId, "rp-csi-1");
    check_id_type!(test_region_name, RegionName, "us-east-1");
    check_id_type!(test_zone_name, ZoneName, "us-east-1a:rack-04");
    check_id_type!(test_container_id, ContainerId, "ctr-task-01");
    check_id_type!(test_vm_id, VmId, "vm-fc-01");
    check_id_type!(test_cgroup_path, CgroupPath, "arbiter.slice:task-01");
    check_id_type!(test_principal_name, PrincipalName, "scheduler-principal:01");
    check_id_type!(test_netns_handle, NetNsHandle, "netns-ctr-01");
    check_id_type!(test_stream_id, StreamId, "stream-fw-01:9001");
    check_id_type!(
        test_operation_uuid,
        OperationUuid,
        "op-uuid-550e8400-e29b-41d4-a716-446655440000"
    );
    check_id_type!(test_offer_filter_id, OfferFilterId, "filter-fw-01:agent-01");

    #[test]
    fn test_zfs_dataset_oci_image_and_signal_number() {
        let zfs = ZfsDatasetName::from_str("tank/arbiter/vol-01:snap_1").unwrap_or_default();
        assert_eq!(zfs.as_str(), "tank/arbiter/vol-01:snap_1");
        assert_eq!(zfs.to_string(), "tank/arbiter/vol-01:snap_1");
        for bad_zfs in [
            "",
            "/tank/vol",
            "tank/vol/",
            "tank//vol",
            "tank/../vol",
            "tank/vol@bad",
        ] {
            assert!(ZfsDatasetName::new(bad_zfs).is_err());
        }

        let hex64 = "b".repeat(64);
        let oci_full =
            OciImageReference::from_str(&format!("localhost:5000/org/app:v1.2.0@sha256:{hex64}"))
                .unwrap_or_default();
        assert_eq!(oci_full.repository(), "localhost:5000/org/app");
        assert_eq!(oci_full.tag(), Some("v1.2.0"));
        assert!(oci_full.digest().is_some());
        assert_eq!(
            oci_full.to_string(),
            format!("localhost:5000/org/app:v1.2.0@sha256:{hex64}")
        );
        assert_eq!(
            oci_full.as_str(),
            format!("localhost:5000/org/app:v1.2.0@sha256:{hex64}")
        );

        let oci_simple = OciImageReference::new("alpine:3.20").unwrap_or_default();
        assert_eq!(oci_simple.repository(), "alpine");
        assert_eq!(oci_simple.tag(), Some("3.20"));
        assert_eq!(oci_simple.digest(), None);

        let oci_reg_no_tag =
            OciImageReference::new("localhost:5000/library/ubuntu").unwrap_or_default();
        assert_eq!(oci_reg_no_tag.repository(), "localhost:5000/library/ubuntu");
        assert_eq!(oci_reg_no_tag.tag(), None);

        for bad_oci in [
            "",
            "alpine :latest",
            "alpine@md5:1234",
            "alpine@sha256:short",
            "/leading/slash:v1",
            "trailing/slash/:v1",
            "emptytag:",
            ":tagonly",
        ] {
            assert!(OciImageReference::new(bad_oci).is_err());
        }

        assert_eq!(SignalNumber::default(), SignalNumber::SIGTERM);
        let sig = SignalNumber::new(9).unwrap_or_default();
        assert_eq!(sig, SignalNumber::SIGKILL);
        assert_eq!(sig.get(), 9);
        assert_eq!(sig.to_string(), "9");
        assert!(SignalNumber::new(0).is_err());
        assert!(SignalNumber::new(65).is_err());

        let _ = rkyv::to_bytes::<rkyv::rancor::Error>(&(zfs, oci_full, sig));
    }

    #[test]
    fn test_pcie_bdf_address() {
        let bdf = PcieBdfAddress::from_str("0000:C1:00.0").unwrap_or_default();
        assert_eq!(bdf.as_str(), "0000:c1:00.0");
        assert_eq!(bdf.to_string(), "0000:c1:00.0");
        let _ = rkyv::to_bytes::<rkyv::rancor::Error>(&bdf);

        for bad_bdf in [
            "",
            "short",
            "0000-c1:00.0",
            "0000:c1-00.0",
            "0000:c1:00:0",
            "0000:zz:00.0",
            "0000:c1:00.8",
        ] {
            assert!(PcieBdfAddress::new(bad_bdf).is_err());
        }
    }

    #[test]
    fn test_jail_id_and_zone_id() {
        assert_eq!(JailId::default().get(), 1);
        assert!(JailId::new(0).is_err());
        assert!(JailId::new(-5).is_err());
        let jid = JailId::new(12).unwrap_or_default();
        assert_eq!(jid.get(), 12);
        assert_eq!(jid.to_string(), "12");

        assert_eq!(ZoneId::default().get(), 1);
        assert!(ZoneId::new(0).is_err());
        assert!(ZoneId::new(-1).is_err());
        let zid = ZoneId::new(7).unwrap_or_default();
        assert_eq!(zid.get(), 7);
        assert_eq!(zid.to_string(), "7");

        let _ = rkyv::to_bytes::<rkyv::rancor::Error>(&(jid, zid));
    }

    #[test]
    fn test_socket_endpoint_and_sha256() {
        let tcp_ep = SocketEndpoint::new("127.0.0.1:5050").unwrap_or_default();
        assert_eq!(tcp_ep.as_str(), "127.0.0.1:5050");
        assert_eq!(tcp_ep.to_string(), "127.0.0.1:5050");
        assert!(!tcp_ep.is_local_ipc());

        let uds_ep = SocketEndpoint::new("/var/run/arbiter/caas.sock").unwrap_or_default();
        assert!(uds_ep.is_local_ipc());

        let pipe_ep = SocketEndpoint::new(r"\\.\pipe\arbiter-caas").unwrap_or_default();
        assert!(pipe_ep.is_local_ipc());

        for bad_ep in [
            "",
            "127.0.0.1\0:5050",
            "/",
            r"\\.\pipe\",
            "no-port",
            ":5050",
            "127.0.0.1:notanumber",
            "127.0.0.1:0",
        ] {
            assert!(SocketEndpoint::new(bad_ep).is_err());
        }

        let valid_hex = "A".repeat(64);
        let dig = Sha256Digest::new(&valid_hex).unwrap_or_default();
        assert_eq!(dig.as_str(), "a".repeat(64));
        assert_eq!(dig.to_string(), "a".repeat(64));
        assert!(Sha256Digest::new("short").is_err());
        assert!(Sha256Digest::new(&"z".repeat(64)).is_err());
    }

    #[test]
    fn test_sandbox_path_pid_and_exit_code() {
        let sp = SandboxPath::new("./bin//worker/./app").unwrap_or_default();
        assert_eq!(sp.as_str(), "bin/worker/app");
        assert_eq!(sp.to_string(), "bin/worker/app");
        for bad_sp in [
            "",
            "./.",
            "/etc/passwd",
            r"bin\app",
            "bin\0app",
            "bin/../etc/passwd",
        ] {
            assert!(SandboxPath::new(bad_sp).is_err());
        }

        assert_eq!(OsProcessId::default().get(), 1);
        assert!(OsProcessId::new(0).is_err());
        let pid = ProcessId::new(4242).unwrap_or_default();
        assert_eq!(pid.get(), 4242);
        assert_eq!(pid.to_string(), "4242");

        assert_eq!(FileDescriptorId::default().get(), 0);
        assert!(FileDescriptorId::new(-1).is_err());
        let fd = FileDescriptorId::new(3).unwrap_or_default();
        assert_eq!(fd.get(), 3);
        assert_eq!(fd.to_string(), "3");
        let _ = rkyv::to_bytes::<rkyv::rancor::Error>(&fd);

        let ok_code = ExitCode::SUCCESS;
        assert_eq!(ok_code.get(), 0);
        assert!(ok_code.is_success());
        assert_eq!(ok_code.terminating_signal(), None);
        assert_eq!(ok_code.to_string(), "0");

        let sigkill_code = ExitCode::new(137);
        assert!(!sigkill_code.is_success());
        assert_eq!(sigkill_code.terminating_signal(), Some(9));
        assert_eq!(ExitCode::new(255).terminating_signal(), None);
    }

    #[test]
    fn test_identifier_bounds_and_invalid_chars() {
        let long_str = "a".repeat(MAX_IDENTIFIER_LEN + 1);
        assert!(TaskId::new(&long_str).is_err());
        assert!(RoleName::new("invalid:char@").is_err());
        assert!(TaskId::new("bad..id").is_err());

        let root_ctr = ContainerId::new("ctr-root-1").unwrap_or_default();
        assert!(!root_ctr.is_nested());
        assert_eq!(root_ctr.parent_container_id(), None);
        let child_ctr = ContainerId::new_nested(&root_ctr, "debug-shell").unwrap_or_default();
        assert!(child_ctr.is_nested());
        assert_eq!(child_ctr.as_str(), "ctr-root-1.debug-shell");
        assert_eq!(child_ctr.parent_container_id(), Some(root_ctr.clone()));
        assert!(ContainerId::new_nested(&root_ctr, "").is_err());
        assert!(ContainerId::new_nested(&root_ctr, &long_str).is_err());
    }

    #[test]
    fn test_fencing_token_operations() {
        assert_eq!(FencingToken::default().get(), 1);
        assert!(FencingToken::new(0).is_err());
        assert!(FencingToken::from_str("not-a-number").is_err());
        assert!(FencingToken::from_str("0").is_err());

        let t1 = FencingToken::from_str("42");
        assert_eq!(t1, ArbiterResult::Ok(FencingToken(42)));
        let token1 = FencingToken(42);
        assert_eq!(token1.get(), 42);
        assert_eq!(token1.to_string(), "42");

        let token2 = token1.next();
        assert_eq!(token2, ArbiterResult::Ok(FencingToken(43)));
        let token2_val = FencingToken(43);

        assert!(token2_val.validate_against(token1).is_ok());
        assert!(token1.validate_against(token1).is_ok());
        assert_eq!(
            token1.validate_against(token2_val),
            Err(ArbiterError::FencingTokenStale {
                presented_token: 42,
                current_token: 43,
            })
        );

        let max_tok = FencingToken(u64::MAX);
        assert_eq!(
            max_tok.next(),
            Err(ArbiterError::ArithmeticOverflow {
                operation: "FencingToken::next".to_owned()
            })
        );
    }

    #[test]
    fn test_spiffe_id_validation() {
        let valid = SpiffeId::from_str("spiffe://arbiter.internal/role/prod_1/task/t-1");
        assert!(valid.is_ok());
        let spiffe = SpiffeId {
            uri: "spiffe://arbiter.internal/role/prod_1/task/t-1".to_owned(),
            trust_domain: "arbiter.internal".to_owned(),
            path: "/role/prod_1/task/t-1".to_owned(),
        };
        assert_eq!(valid, Ok(spiffe.clone()));
        assert_eq!(
            spiffe.as_str(),
            "spiffe://arbiter.internal/role/prod_1/task/t-1"
        );
        assert_eq!(spiffe.trust_domain(), "arbiter.internal");
        assert_eq!(spiffe.path(), "/role/prod_1/task/t-1");
        assert_eq!(
            spiffe.to_string(),
            "spiffe://arbiter.internal/role/prod_1/task/t-1"
        );

        // Exceeds max len
        let huge = format!("spiffe://domain/{}", "a".repeat(MAX_SPIFFE_URI_LEN));
        assert!(SpiffeId::new(&huge).is_err());

        // Missing scheme
        assert!(SpiffeId::new("https://arbiter.internal/node/1").is_err());

        // Missing path slash
        assert!(SpiffeId::new("spiffe://arbiter.internal").is_err());

        // Empty domain or path
        assert!(SpiffeId::new("spiffe:///path").is_err());
        assert!(SpiffeId::new("spiffe://domain/").is_err());

        // Disallowed character
        assert!(SpiffeId::new("spiffe://domain/path with space").is_err());
    }

    #[test]
    fn test_rkyv_and_serde_roundtrip_for_ids() {
        let id = AgentId(String::from("agent-rkyv-1"));
        let all_ids = (
            id.clone(),
            SocketEndpoint::default(),
            Sha256Digest::default(),
            SandboxPath::default(),
            OsProcessId::default(),
            ExitCode::default(),
            FencingToken::default(),
            SpiffeId::default(),
        );
        let _ = rkyv::to_bytes::<rkyv::rancor::Error>(&all_ids);
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&id);
        assert!(bytes.is_ok());
        let encoded = bytes.unwrap_or_default();
        let decoded: Result<AgentId, rkyv::rancor::Error> = rkyv::from_bytes(&encoded);
        assert_eq!(decoded.ok(), Some(id));
    }

    proptest! {
        #[test]
        fn prop_valid_identifier_roundtrip(s in "[a-zA-Z0-9_:-]{1,64}") {
            let id = AgentId::new(&s);
            prop_assert!(id.is_ok());
        }
    }
}
