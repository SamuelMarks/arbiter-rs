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
        #[rkyv(
            compare(PartialEq, PartialOrd),
            derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash)
        )]
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
    /// Unique identifier for an atomic Gang / TaskGroup workload.
    TaskGroupId,
    "TaskGroupId"
);

define_string_id!(
    /// Unique identifier for a resource Offer sent to a Framework.
    OfferId,
    "OfferId"
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
#[rkyv(compare(PartialEq), derive(Debug))]
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
#[rkyv(compare(PartialEq), derive(Debug))]
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

    check_id_type!(test_agent_id, AgentId, "agent-01.prod:rack_1");
    check_id_type!(test_framework_id, FrameworkId, "fw-1");
    check_id_type!(test_task_id, TaskId, "task-1");
    check_id_type!(test_task_group_id, TaskGroupId, "tg-1");
    check_id_type!(test_offer_id, OfferId, "offer-1");
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

    #[test]
    fn test_identifier_bounds_and_invalid_chars() {
        let long_str = "a".repeat(MAX_IDENTIFIER_LEN + 1);
        assert!(matches!(
            TaskId::new(&long_str),
            Err(ArbiterError::InvalidIdentifierCharacters { .. })
        ));

        assert!(matches!(
            RoleName::new("invalid/slash"),
            Err(ArbiterError::InvalidIdentifierCharacters { .. })
        ));
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
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&id);
        assert!(bytes.is_ok());
        let encoded = bytes.unwrap_or_default();
        let decoded: Result<AgentId, rkyv::rancor::Error> = rkyv::from_bytes(&encoded);
        assert_eq!(decoded.ok(), Some(id));
    }

    proptest! {
        #[test]
        fn prop_valid_identifier_roundtrip(s in "[a-zA-Z0-9_.:-]{1,64}") {
            let id = AgentId::new(&s);
            prop_assert!(id.is_ok());
        }
    }
}
