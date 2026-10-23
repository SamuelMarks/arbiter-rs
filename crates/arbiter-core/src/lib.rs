//! Core domain primitives, unified error model, hardware topology graph, and resource algebra for Arbiter.
//!
//! This crate forms the foundation of the Arbiter resource allocator and orchestrator.

#![forbid(missing_docs)]
#![forbid(clippy::missing_docs_in_private_items)]

pub mod error;
pub mod ids;
pub mod platform;
pub mod resources;
pub mod topology;
pub mod units;
pub mod workload;

pub use error::{
    ArbiterError, ArbiterResult, CniPluginError, CriuCheckpointError, FuseMountError,
    IoOperationError, JsonCodecError, RkyvCodecError, SignalDeliveryError, TerminalRawModeError,
    ZfsCommandError,
};

/// Returns the crate identifier for verification.
///
/// # Returns
///
/// The static crate name `"arbiter-core"`.
pub const fn crate_name() -> &'static str {
    "arbiter-core"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crate_name() {
        assert_eq!(crate_name(), "arbiter-core");
    }
}
