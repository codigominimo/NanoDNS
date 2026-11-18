//! Optional HTTP management API for NanoDNS.
//!
//! Exposes status, statistics and sanitized configuration over the shared
//! minimal HTTP server. Access is restricted by socket-peer network allow-list
//! and an optional bearer token.

mod auth;
mod error;
mod server;

pub use error::ApiError;
pub use server::ApiServer;
