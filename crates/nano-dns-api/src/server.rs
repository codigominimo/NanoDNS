//! Optional HTTP management API server.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use nano_dns_core::config::{ApiConfig, Config};
use nano_dns_core::error::Result;
use nano_dns_core::traits::StatsSink;
use nano_dns_http::{HttpServer, Request, Response};
use serde::Serialize;
use tracing::warn;

use crate::auth::{self, Access};
use crate::error::ApiError;

/// HTTP status codes used by the API.
const OK: u16 = 200;
const UNAUTHORIZED: u16 = 401;
const FORBIDDEN: u16 = 403;
const NOT_FOUND: u16 = 404;
const METHOD_NOT_ALLOWED: u16 = 405;
const INTERNAL_ERROR: u16 = 500;

/// State shared with every accepted connection.
struct Inner {
    config: ApiConfig,
    instance_name: String,
    resolver_mode: String,
    dns_cache_enabled: bool,
    blocker_enabled: bool,
    storage_enabled: bool,
    stats_enabled: bool,
    stats: Option<Arc<dyn StatsSink>>,
    started_at: Instant,
}

/// A bound HTTP listener for the management API.
pub struct ApiServer {
    server: HttpServer<Inner>,
}

impl ApiServer {
    /// Bind the configured API address.
    pub async fn bind(config: &Config, stats: Option<Arc<dyn StatsSink>>) -> Result<Self> {
        let address = SocketAddr::new(config.api.listen, config.api.port);
        let inner = Arc::new(Inner {
            config: config.api.clone(),
            instance_name: config.general.instance_name.clone(),
            resolver_mode: format!("{:?}", config.resolver.mode),
            dns_cache_enabled: config.dns_cache.enabled,
            blocker_enabled: config.blocker.enabled,
            storage_enabled: config.storage.enabled,
            stats_enabled: config.stats.enabled,
            stats,
            started_at: Instant::now(),
        });
        let server = HttpServer::bind(address, inner, handle_request, "api")
            .await
            .map_err(ApiError::from)?;
        Ok(Self { server })
    }

    /// Accept connections until a shutdown signal arrives.
    pub async fn serve_with_signal<S>(self, signal: S) -> Result<()>
    where
        S: Future<Output = ()>,
    {
        self.server
            .serve_with_signal(signal)
            .await
            .map_err(ApiError::from)?;
        Ok(())
    }

    /// Bound local address, useful for tests and diagnostics.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.server.local_addr()
    }
}

/// Authorize and dispatch one request using the shared HTTP handler signature.
fn handle_request(request: &Request, peer: IpAddr, inner: &Inner) -> Response {
    match authorize_request(inner, request, peer) {
        Access::NetworkDenied => {
            warn!(%peer, "API request from unauthorized network");
            error_response(FORBIDDEN, "network not allowed")
        }
        Access::TokenDenied => {
            warn!(%peer, "API request with invalid token");
            error_response(UNAUTHORIZED, "invalid or missing bearer token")
        }
        Access::Allowed => route(inner, request),
    }
}

/// Check network and token access using only the socket peer identity.
fn authorize_request(inner: &Inner, request: &Request, peer: IpAddr) -> Access {
    auth::authorize(&inner.config, peer, request.header("authorization"))
}

/// Dispatch an authorized request to its handler.
fn route(inner: &Inner, request: &Request) -> Response {
    if request.method != "GET" {
        return error_response(METHOD_NOT_ALLOWED, "only GET is supported")
            .with_header("Allow", "GET");
    }

    match request.route_path() {
        "/api/v1/status" => json_response(OK, StatusResponse::from(inner)),
        "/api/v1/stats" => stats_response(inner),
        "/api/v1/config" => json_response(OK, ConfigResponse::from(inner)),
        _ => error_response(NOT_FOUND, "unknown endpoint"),
    }
}

/// Build the statistics response, or 404 when statistics are unavailable.
fn stats_response(inner: &Inner) -> Response {
    match &inner.stats {
        Some(stats) => json_response(OK, stats.snapshot()),
        None => error_response(NOT_FOUND, "statistics are not enabled"),
    }
}

fn json_response<T: Serialize>(status: u16, value: T) -> Response {
    match Response::json(status, value) {
        Ok(response) => response,
        Err(error) => {
            warn!(%error, "cannot encode API response");
            error_response(INTERNAL_ERROR, "cannot encode response")
        }
    }
}

fn error_response(status: u16, message: &str) -> Response {
    json_response(
        status,
        serde_json::json!({ "error": message, "status": status }),
    )
}

#[derive(Serialize)]
struct StatusResponse {
    status: &'static str,
    version: &'static str,
    instance: String,
    uptime_secs: u64,
    statistics: bool,
}

impl From<&Inner> for StatusResponse {
    fn from(inner: &Inner) -> Self {
        Self {
            status: "ok",
            version: env!("CARGO_PKG_VERSION"),
            instance: inner.instance_name.clone(),
            uptime_secs: inner.started_at.elapsed().as_secs(),
            statistics: inner.stats_enabled,
        }
    }
}

#[derive(Serialize)]
struct ConfigResponse {
    resolver_mode: String,
    dns_cache_enabled: bool,
    blocker_enabled: bool,
    storage_enabled: bool,
    statistics_enabled: bool,
}

impl From<&Inner> for ConfigResponse {
    fn from(inner: &Inner) -> Self {
        Self {
            resolver_mode: inner.resolver_mode.clone(),
            dns_cache_enabled: inner.dns_cache_enabled,
            blocker_enabled: inner.blocker_enabled,
            storage_enabled: inner.storage_enabled,
            statistics_enabled: inner.stats_enabled,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use nano_dns_core::config::ResolverMode;

    use super::*;

    fn inner() -> Inner {
        Inner {
            config: ApiConfig::default(),
            instance_name: "NanoDNS".to_owned(),
            resolver_mode: format!("{:?}", ResolverMode::Forward),
            dns_cache_enabled: true,
            blocker_enabled: true,
            storage_enabled: false,
            stats_enabled: false,
            stats: None,
            started_at: Instant::now(),
        }
    }

    fn body(response: &Response) -> serde_json::Value {
        serde_json::from_slice(&response.body).expect("API responses are JSON")
    }

    #[test]
    fn status_route_returns_ok() {
        let response = route(&inner(), &Request::new("GET", "/api/v1/status"));
        assert_eq!(response.status, OK);
        assert_eq!(body(&response)["status"], "ok");
        assert_eq!(body(&response)["instance"], "NanoDNS");
    }

    #[test]
    fn config_route_hides_secrets() {
        let response = route(&inner(), &Request::new("GET", "/api/v1/config"));
        assert_eq!(response.status, OK);
        assert!(body(&response).get("token").is_none());
        assert_eq!(body(&response)["dns_cache_enabled"], true);
    }

    #[test]
    fn stats_route_requires_statistics() {
        let response = route(&inner(), &Request::new("GET", "/api/v1/stats"));
        assert_eq!(response.status, NOT_FOUND);
    }

    #[test]
    fn unknown_route_returns_not_found() {
        let response = route(&inner(), &Request::new("GET", "/api/v1/unknown"));
        assert_eq!(response.status, NOT_FOUND);
    }

    #[test]
    fn post_is_not_allowed() {
        let response = route(&inner(), &Request::new("POST", "/api/v1/status"));
        assert_eq!(response.status, METHOD_NOT_ALLOWED);
        assert!(response.extra_headers.contains(&("Allow", "GET")));
    }

    #[test]
    fn query_string_is_ignored() {
        let response = route(&inner(), &Request::new("GET", "/api/v1/status?verbose=1"));
        assert_eq!(response.status, OK);
    }

    #[test]
    fn peer_ip_is_used_for_authorization() {
        let inner = inner();
        assert_eq!(
            authorize_request(
                &inner,
                &Request::new("GET", "/api/v1/status"),
                IpAddr::V4(Ipv4Addr::LOCALHOST),
            ),
            Access::Allowed
        );
    }
}
