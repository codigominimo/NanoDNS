//! Errors produced while loading domain lists.

use std::path::PathBuf;

/// Block list loading failures.
#[derive(Debug, thiserror::Error)]
pub enum BlockerError {
    /// Remote lists require network access and are not supported in this phase.
    #[error("remote block list source {0} is not supported; use a local file")]
    RemoteSource(String),
    /// A configured list file could not be read.
    #[error("cannot read block list {}: {source}", path.display())]
    Io {
        /// Path that failed to load.
        path: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// The list file is not valid UTF-8.
    #[error("block list {} is not valid UTF-8: {source}", path.display())]
    Encoding {
        /// Path that failed to decode.
        path: PathBuf,
        /// Underlying conversion error.
        source: std::string::FromUtf8Error,
    },
}

impl From<BlockerError> for nano_dns_core::error::Error {
    fn from(error: BlockerError) -> Self {
        Self::Runtime(error.to_string())
    }
}
