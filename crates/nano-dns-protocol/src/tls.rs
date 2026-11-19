//! TLS certificate loading shared by the DoT and DoH listeners.
//!
//! Hickory owns the TLS handshake and the protocol dispatch; this module only
//! turns the configured PEM files into a rustls certificate resolver.

use std::path::Path;
use std::sync::Arc;

use hickory_server::net::tls::default_provider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::ResolvesServerCert;
use rustls::sign::{CertifiedKey, SingleCertAndKey};

use crate::error::ProtocolError;

/// Load a PEM certificate chain and private key into a rustls resolver.
pub(crate) fn cert_resolver(
    cert_path: &Path,
    key_path: &Path,
) -> Result<Arc<dyn ResolvesServerCert>, ProtocolError> {
    let chain = CertificateDer::pem_file_iter(cert_path)
        .map_err(|error| {
            ProtocolError::Tls(format!(
                "cannot read certificate '{}': {error}",
                cert_path.display()
            ))
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            ProtocolError::Tls(format!(
                "invalid certificate '{}': {error}",
                cert_path.display()
            ))
        })?;
    if chain.is_empty() {
        return Err(ProtocolError::Tls(format!(
            "certificate '{}' contains no certificates",
            cert_path.display()
        )));
    }

    let key = PrivateKeyDer::from_pem_file(key_path).map_err(|error| {
        ProtocolError::Tls(format!(
            "cannot read private key '{}': {error}",
            key_path.display()
        ))
    })?;

    let provider = default_provider();
    let certified = CertifiedKey::from_der(chain, key, &provider)
        .map_err(|error| ProtocolError::Tls(format!("invalid certificate/key pair: {error}")))?;
    Ok(Arc::new(SingleCertAndKey::from(certified)))
}
