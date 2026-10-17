//! Zero-trust security (mTLS, SPIFFE, RBAC/ABAC, AEAD secrets) and dual-protocol QUIC/HTTP transport for Arbiter.

#![forbid(missing_docs)]
#![forbid(clippy::missing_docs_in_private_items)]

pub mod http;
pub mod quic;
pub mod security;

/// Returns the crate identifier for verification.
///
/// # Returns
///
/// The static crate name `"arbiter-net"`.
pub const fn crate_name() -> &'static str {
    "arbiter-net"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crate_name() {
        assert_eq!(crate_name(), "arbiter-net");
    }
}
