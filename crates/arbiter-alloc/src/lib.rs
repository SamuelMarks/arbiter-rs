//! Hierarchical Dominant Resource Fairness (HDRF), topology bin-packer, and gang scheduler for Arbiter.

#![forbid(missing_docs)]
#![forbid(clippy::missing_docs_in_private_items)]

pub mod drf;
pub mod engine;
pub mod federation;
pub mod gang;
pub mod preemption;
pub mod topology_packer;

/// Returns the crate identifier for verification.
///
/// # Returns
///
/// The static crate name `"arbiter-alloc"`.
pub const fn crate_name() -> &'static str {
    "arbiter-alloc"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crate_name() {
        assert_eq!(crate_name(), "arbiter-alloc");
    }
}
