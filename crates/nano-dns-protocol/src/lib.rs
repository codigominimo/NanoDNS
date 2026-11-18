//! DNS transport layer for NanoDNS.
//!
//! This crate owns the Hickory DNS integration and keeps protocol-specific
//! types away from the protocol-agnostic core.

pub mod error;
pub mod handler;
pub mod server;

pub use error::ProtocolError;
pub use handler::{NanoRequestHandler, RequestLimits};
pub use server::DnsServer;
