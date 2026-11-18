//! Optional server-rendered web dashboard for NanoDNS.
//!
//! Serves a read-only overview of status and statistics over the shared
//! minimal HTTP server. The interface is always restricted to loopback peers
//! because its configuration exposes no access-control list.

mod error;
mod page;
mod server;

pub use error::WebError;
pub use server::WebServer;
