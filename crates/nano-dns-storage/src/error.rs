//! Errors produced by SQLite persistence.

use std::path::PathBuf;

/// SQLite persistence failures.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    /// Persistence was requested while storage is disabled.
    #[error("SQLite storage is disabled")]
    Disabled,
    /// The database parent directory could not be created.
    #[error("cannot create storage directory {}: {source}", path.display())]
    CreateDirectory {
        /// Directory that could not be created.
        path: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// The database could not be opened.
    #[error("cannot open database {}: {source}", path.display())]
    Open {
        /// Database path.
        path: PathBuf,
        /// Underlying SQLite error.
        source: rusqlite::Error,
    },
    /// The database schema could not be initialized.
    #[error("cannot initialize database schema: {0}")]
    Schema(String),
    /// The background writer thread could not be started.
    #[error("cannot start database writer: {0}")]
    Spawn(std::io::Error),
    /// The bounded event queue is full.
    #[error("query history queue is full")]
    QueueFull,
    /// The background writer is no longer running.
    #[error("database writer is not running")]
    WriterStopped,
    /// Events could not be written to the database.
    #[error("database write failed: {0}")]
    Write(String),
}

impl From<StorageError> for nano_dns_core::error::Error {
    fn from(error: StorageError) -> Self {
        Self::Runtime(error.to_string())
    }
}
