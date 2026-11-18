//! Errors produced by the optional web interface.

use nano_dns_http::HttpError;

/// Web server failures.
#[derive(Debug, thiserror::Error)]
pub enum WebError {
    /// The shared HTTP server failed.
    #[error(transparent)]
    Http(#[from] HttpError),
}

impl From<WebError> for nano_dns_core::error::Error {
    fn from(error: WebError) -> Self {
        Self::Runtime(error.to_string())
    }
}
