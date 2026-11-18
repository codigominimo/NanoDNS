//! Minimal shared HTTP/1.1 server for NanoDNS management interfaces.
//!
//! Provides request parsing, response writing and an accept loop driven by a
//! caller-supplied handler. Routing, authentication and content live in the
//! crates that depend on this one, so no HTTP framework is pulled into the
//! minimal build.

mod error;
mod server;

pub use error::HttpError;
pub use server::{HttpServer, Request, Response};
