//! Pluggable state store, embedded Raft consensus, shared election/fencing plane, and multi-cluster federation for Arbiter.

#![forbid(missing_docs)]
#![forbid(clippy::missing_docs_in_private_items)]

pub mod election;
pub mod external;
pub mod federation;
pub mod ha_generic;
pub mod memory;
pub mod raft;
pub mod traits;

/// Returns the crate identifier for verification.
///
/// # Returns
///
/// The static crate name `"arbiter-store"`.
pub const fn crate_name() -> &'static str {
    "arbiter-store"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crate_name() {
        assert_eq!(crate_name(), "arbiter-store");
    }
}
