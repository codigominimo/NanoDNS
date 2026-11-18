//! Errors produced by the minimal HTTP server.

use std::net::SocketAddr;

/// Failures from binding, accepting, reading or writing HTTP connections.
#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    /// The listener could not be bound.
    #[error("cannot bind HTTP listener on {address}: {source}")]
    Bind {
        /// Address that could not be bound.
        address: SocketAddr,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// A connection could not be accepted.
    #[error("cannot accept HTTP connection: {0}")]
    Accept(std::io::Error),
    /// A request could not be read.
    #[error("cannot read HTTP request: {0}")]
    Read(std::io::Error),
    /// A request head was malformed, oversized or timed out.
    #[error("invalid HTTP request: {0}")]
    InvalidRequest(&'static str),
    /// A response could not be written.
    #[error("cannot write HTTP response: {0}")]
    Write(std::io::Error),
    /// A JSON body could not be encoded.
    #[error("cannot encode JSON response: {0}")]
    Encode(serde_json::Error),
}
