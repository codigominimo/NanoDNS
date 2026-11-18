//! Optional SQLite persistence for NanoDNS.
//!
//! Completed queries are queued to a dedicated writer thread, batched into
//! transactions and stored without blocking DNS request handling. The crate
//! implements the protocol-neutral `Storage` trait from `nano-dns-core`.

pub mod error;
mod schema;
pub mod sqlite;

pub use error::StorageError;
pub use sqlite::SqliteStorage;
