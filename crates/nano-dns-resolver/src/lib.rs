//! DNS resolver implementations for NanoDNS.
//!
//! Forwarding is always available. Iterative recursive resolution is gated
//! behind the `recursive` feature so minimal builds stay small.

pub mod error;
pub mod forwarder;
pub(crate) mod response;
pub(crate) mod transport;

#[cfg(feature = "recursive")]
pub mod recursive;

pub use error::ResolverError;
pub use forwarder::ForwardResolver;
#[cfg(feature = "recursive")]
pub use recursive::RecursiveResolver;
