//! Authentication and network access control for the management API.
//!
//! Client identity always comes from the accepted socket peer, never from a
//! request header. This matches the DNS listener policy.

use std::net::IpAddr;

use nano_dns_core::config::ApiConfig;

/// Result of checking an incoming API request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Access {
    /// The request is allowed.
    Allowed,
    /// The peer is outside the configured networks.
    NetworkDenied,
    /// The bearer token is missing or incorrect.
    TokenDenied,
}

/// Check whether a peer may call the API.
pub(crate) fn authorize(config: &ApiConfig, peer: IpAddr, authorization: Option<&str>) -> Access {
    if !network_allowed(config, peer) {
        return Access::NetworkDenied;
    }
    match &config.token {
        Some(expected) => {
            let provided = authorization
                .and_then(|value| value.strip_prefix("Bearer "))
                .unwrap_or_default();
            if constant_time_eq(provided.as_bytes(), expected.as_bytes()) {
                Access::Allowed
            } else {
                Access::TokenDenied
            }
        }
        None => Access::Allowed,
    }
}

/// Empty allow-lists default to loopback only.
fn network_allowed(config: &ApiConfig, peer: IpAddr) -> bool {
    if config.allowed_networks.is_empty() {
        peer.is_loopback()
    } else {
        config
            .allowed_networks
            .iter()
            .any(|network| network.contains(&peer))
    }
}

/// Compare two byte slices without short-circuiting on the first difference.
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (a, b) in left.iter().zip(right) {
        difference |= a ^ b;
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use ipnet::{IpNet, Ipv4Net};

    use super::*;

    fn config(token: Option<&str>, networks: Vec<IpNet>) -> ApiConfig {
        ApiConfig {
            enabled: true,
            listen: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 8080,
            token: token.map(str::to_owned),
            allowed_networks: networks,
        }
    }

    fn local() -> IpAddr {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    }

    fn remote() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5))
    }

    #[test]
    fn loopback_is_allowed_by_default() {
        assert_eq!(
            authorize(&config(None, Vec::new()), local(), None),
            Access::Allowed
        );
        assert_eq!(
            authorize(&config(None, Vec::new()), remote(), None),
            Access::NetworkDenied
        );
    }

    #[test]
    fn token_is_required_when_configured() {
        let api = config(Some("secret"), Vec::new());
        assert_eq!(authorize(&api, local(), None), Access::TokenDenied);
        assert_eq!(
            authorize(&api, local(), Some("Bearer wrong")),
            Access::TokenDenied
        );
        assert_eq!(
            authorize(&api, local(), Some("Bearer secret")),
            Access::Allowed
        );
    }

    #[test]
    fn network_is_checked_before_token() {
        let api = config(Some("secret"), Vec::new());
        assert_eq!(
            authorize(&api, remote(), Some("Bearer secret")),
            Access::NetworkDenied
        );
    }

    #[test]
    fn explicit_networks_are_honored() {
        let api = config(
            None,
            vec![IpNet::V4(
                Ipv4Net::new(Ipv4Addr::new(203, 0, 113, 0), 24).expect("valid network"),
            )],
        );
        assert_eq!(authorize(&api, remote(), None), Access::Allowed);
        assert_eq!(authorize(&api, local(), None), Access::NetworkDenied);
    }

    #[test]
    fn token_comparison_is_exact() {
        assert!(constant_time_eq(b"secret", b"secret"));
        assert!(!constant_time_eq(b"secret", b"secrex"));
        assert!(!constant_time_eq(b"secret", b"secret "));
        assert!(!constant_time_eq(b"a", b"ab"));
    }
}
