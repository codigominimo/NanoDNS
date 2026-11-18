//! Errors produced by the forwarding resolver.

use std::net::SocketAddr;
use std::time::Duration;

/// Upstream communication and response validation errors.
#[derive(Debug, thiserror::Error)]
pub enum ResolverError {
    /// The requested resolver mode is not implemented in this phase.
    #[error("{0}")]
    Unsupported(String),
    /// Network I/O failed.
    #[error("upstream {address} I/O error: {source}")]
    Io {
        /// Upstream contacted.
        address: SocketAddr,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// The upstream did not answer before the configured deadline.
    #[error("upstream {address} timed out after {timeout:?}")]
    Timeout {
        /// Upstream contacted.
        address: SocketAddr,
        /// Configured timeout.
        timeout: Duration,
    },
    /// The upstream response was malformed or did not match the query.
    #[error("invalid response from upstream {address}: {reason}")]
    InvalidResponse {
        /// Upstream contacted.
        address: SocketAddr,
        /// Human-readable validation failure.
        reason: String,
    },
    /// No configured upstream produced a usable response.
    #[error("no upstream resolver returned a valid response")]
    NoUpstream,
    /// The validated response could not be re-encoded.
    #[error("cannot encode upstream response: {0}")]
    Encode(String),
}

impl From<ResolverError> for nano_dns_core::error::Error {
    fn from(error: ResolverError) -> Self {
        Self::Runtime(error.to_string())
    }
}
