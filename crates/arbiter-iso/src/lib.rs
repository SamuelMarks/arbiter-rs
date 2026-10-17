//! Cross-platform OS isolators (`cgroups`, Jails, Zones, Job Objects, sandbox), accelerators, OCI, and `MicroVMs` for Arbiter.

#![forbid(missing_docs)]
#![forbid(clippy::missing_docs_in_private_items)]

pub mod accelerator;
pub mod native;
pub mod pipeline;
pub mod runtime;

/// Returns the crate identifier for verification.
///
/// # Returns
///
/// The static crate name `"arbiter-iso"`.
pub const fn crate_name() -> &'static str {
    "arbiter-iso"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crate_name() {
        assert_eq!(crate_name(), "arbiter-iso");
    }
}
