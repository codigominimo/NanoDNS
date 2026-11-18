//! Errors produced by the optional REST API.

use nano_dns_http::HttpError;

/// API server failures.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    /// The shared HTTP server failed.
    #[error(transparent)]
    Http(#[from] HttpError),
}

impl From<ApiError> for nano_dns_core::error::Error {
    fn from(error: ApiError) -> Self {
        Self::Runtime(error.to_string())
    }
}
