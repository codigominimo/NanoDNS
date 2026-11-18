//! Domain filtering for NanoDNS.
//!
//! The crate loads local domain lists and evaluates global and per-client
//! rules. It implements the core `Policy` trait and does not depend on Hickory.

pub mod error;
pub mod list;
pub mod policy;

pub use error::BlockerError;
pub use policy::DomainBlocker;
