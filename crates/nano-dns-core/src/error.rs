//! Error types shared by all NanoDNS crates.

use std::path::PathBuf;

/// Errors produced by configuration loading and validation.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The configuration file could not be read.
    #[error("cannot read configuration file {}: {source}", path.display())]
    Read {
        /// Path that could not be read.
        path: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// The configuration file is not valid JSON.
    #[error("invalid JSON in configuration file {}: {source}", path.display())]
    Json {
        /// Path of the malformed file.
        path: PathBuf,
        /// Underlying JSON error.
        source: serde_json::Error,
    },
    /// A semantically invalid configuration value was detected.
    #[error("invalid configuration: {0}")]
    Validation(String),
}

/// Top-level NanoDNS error type.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Configuration error.
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// Runtime or I/O error.
    #[error("{0}")]
    Runtime(String),
}

/// Result alias used throughout NanoDNS.
pub type Result<T> = std::result::Result<T, Error>;

/// Result alias for configuration operations.
pub type ConfigResult<T> = std::result::Result<T, ConfigError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_error_is_displayable() {
        let error = ConfigError::Validation("invalid port".to_owned());
        assert_eq!(error.to_string(), "invalid configuration: invalid port");
    }
}
