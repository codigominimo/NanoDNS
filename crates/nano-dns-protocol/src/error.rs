//! Errors produced by the DNS transport layer.

use std::net::SocketAddr;

/// Transport and server lifecycle errors.
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    /// A listener could not be bound.
    #[error("cannot bind DNS listener on {address}: {source}")]
    Bind {
        /// Address that could not be bound.
        address: SocketAddr,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// The Hickory server task reported a fatal error.
    #[error("DNS server task failed: {0}")]
    Server(String),
    /// Graceful shutdown failed.
    #[error("DNS server shutdown failed: {0}")]
    Shutdown(String),
}

impl From<ProtocolError> for nano_dns_core::error::Error {
    fn from(error: ProtocolError) -> Self {
        Self::Runtime(error.to_string())
    }
}
