//! Optional server-rendered web dashboard for NanoDNS.
//!
//! Serves status, statistics and optional ad-blocker controls over the shared
//! minimal HTTP server. The interface is always restricted to loopback peers
//! because its configuration exposes no access-control list, and state-changing
//! requests also require a per-process token rendered in the dashboard.

mod error;
mod page;
mod server;

pub use error::WebError;
pub use server::WebServer;
