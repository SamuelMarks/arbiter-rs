//! Cross-platform CPU, NUMA, GPU, TPU, and fabric hardware discovery and telemetry probes for Arbiter.

#![forbid(missing_docs)]
#![forbid(clippy::missing_docs_in_private_items)]

pub mod cpu;
pub mod fabric;
pub mod gpu;
pub mod tpu;
pub mod traits;

/// Returns the crate identifier for verification.
///
/// # Returns
///
/// The static crate name `"arbiter-probe"`.
pub const fn crate_name() -> &'static str {
    "arbiter-probe"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crate_name() {
        assert_eq!(crate_name(), "arbiter-probe");
    }
}
