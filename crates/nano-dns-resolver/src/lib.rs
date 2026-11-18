//! DNS resolution crates for NanoDNS.
//!
//! This phase provides a forwarding resolver. Recursive resolution is a
//! later phase.

pub mod error;
pub mod forwarder;

pub use error::ResolverError;
pub use forwarder::ForwardResolver;
