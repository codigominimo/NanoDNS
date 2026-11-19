//! DNS resolver implementations for NanoDNS.
//!
//! Forwarding, iterative recursion and DNSSEC validation are all compiled in.
//! The JSON configuration decides which resolver is actually used.

pub mod dnssec;
pub mod error;
pub mod forwarder;
pub mod recursive;
pub(crate) mod response;
pub(crate) mod transport;

pub use dnssec::DnssecResolver;
pub use error::ResolverError;
pub use forwarder::ForwardResolver;
pub use recursive::RecursiveResolver;
