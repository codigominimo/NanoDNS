//! Shared foundation for NanoDNS: configuration, errors, models, interfaces
//! and runtime helpers.
//!
//! This crate intentionally has no dependency on a concrete DNS protocol
//! implementation so that external libraries remain replaceable.

pub mod config;
pub mod error;
pub mod model;
pub mod runtime;
pub mod traits;

pub use config::{Config, Features};
pub use error::{Error, Result};
