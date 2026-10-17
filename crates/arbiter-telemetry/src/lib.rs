//! Prometheus/OpenTelemetry metrics, hardware counters, service discovery, and health probes for Arbiter.

#![forbid(missing_docs)]
#![forbid(clippy::missing_docs_in_private_items)]

pub mod discovery;
pub mod metrics;
pub mod wire_accounting;

/// Returns the crate identifier for verification.
///
/// # Returns
///
/// The static crate name `"arbiter-telemetry"`.
pub const fn crate_name() -> &'static str {
    "arbiter-telemetry"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crate_name() {
        assert_eq!(crate_name(), "arbiter-telemetry");
    }
}
