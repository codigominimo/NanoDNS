//! Optional server-rendered web interface.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use nano_dns_core::config::Config;
use nano_dns_core::error::Result;
use nano_dns_core::traits::StatsSink;
use nano_dns_http::{HttpServer, Request, Response};
use tracing::warn;

use crate::error::WebError;
use crate::page::{self, PageData};

const OK: u16 = 200;
const FORBIDDEN: u16 = 403;
const NOT_FOUND: u16 = 404;
const METHOD_NOT_ALLOWED: u16 = 405;

/// State shared with every accepted connection.
struct Inner {
    instance_name: String,
    resolver_mode: String,
    started_at: Instant,
    stats: Option<Arc<dyn StatsSink>>,
}

/// A bound HTTP listener for the web dashboard.
pub struct WebServer {
    server: HttpServer<Inner>,
}

impl WebServer {
    /// Bind the configured web address.
    pub async fn bind(config: &Config, stats: Option<Arc<dyn StatsSink>>) -> Result<Self> {
        let address = SocketAddr::new(config.web.listen, config.web.port);
        let inner = Arc::new(Inner {
            instance_name: config.general.instance_name.clone(),
            resolver_mode: format!("{:?}", config.resolver.mode),
            started_at: Instant::now(),
            stats,
        });
        let server = HttpServer::bind(address, inner, handle_request, "web")
            .await
            .map_err(WebError::from)?;
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
            .map_err(WebError::from)?;
        Ok(())
    }

    /// Bound local address, useful for tests and diagnostics.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.server.local_addr()
    }
}

/// The dashboard is loopback-only: `WebConfig` has no allow-list by design.
fn handle_request(request: &Request, peer: IpAddr, inner: &Inner) -> Response {
    if !peer.is_loopback() {
        warn!(%peer, "web request from non-loopback address");
        return Response::text(FORBIDDEN, "Forbidden");
    }
    if request.method != "GET" {
        return Response::text(METHOD_NOT_ALLOWED, "Method Not Allowed")
            .with_header("Allow", "GET");
    }

    match request.route_path() {
        "/" => {
            let data = PageData {
                instance: &inner.instance_name,
                version: env!("CARGO_PKG_VERSION"),
                uptime_secs: inner.started_at.elapsed().as_secs(),
                resolver_mode: &inner.resolver_mode,
                stats: inner.stats.as_ref().map(|stats| stats.snapshot()),
            };
            Response::html(OK, page::render(&data))
        }
        "/health" => Response::text(OK, "ok\n"),
        _ => Response::text(NOT_FOUND, "Not Found"),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use nano_dns_core::config::ResolverMode;
    use nano_dns_core::model::{QueryEvent, StatsSnapshot};

    use super::*;

    struct StubStats;

    impl StatsSink for StubStats {
        fn record(&self, _event: &QueryEvent) {}

        fn snapshot(&self) -> StatsSnapshot {
            StatsSnapshot {
                total_queries: 4,
                ..StatsSnapshot::default()
            }
        }
    }

    fn inner() -> Inner {
        Inner {
            instance_name: "NanoDNS".to_owned(),
            resolver_mode: format!("{:?}", ResolverMode::Forward),
            started_at: Instant::now() - Duration::from_secs(10),
            stats: None,
        }
    }

    fn get(path: &str) -> Request {
        Request::new("GET", path)
    }

    #[test]
    fn root_returns_html_dashboard() {
        let response = handle_request(&get("/"), IpAddr::from([127, 0, 0, 1]), &inner());
        assert_eq!(response.status, OK);
        assert_eq!(response.content_type, "text/html; charset=utf-8");
        let body = String::from_utf8(response.body).expect("HTML body is UTF-8");
        assert!(body.contains("<!DOCTYPE html>"));
    }

    #[test]
    fn health_returns_plain_text() {
        let response = handle_request(&get("/health"), IpAddr::from([127, 0, 0, 1]), &inner());
        assert_eq!(response.status, OK);
        assert_eq!(response.content_type, "text/plain; charset=utf-8");
    }

    #[test]
    fn unknown_path_returns_not_found() {
        let response = handle_request(&get("/nope"), IpAddr::from([127, 0, 0, 1]), &inner());
        assert_eq!(response.status, NOT_FOUND);
    }

    #[test]
    fn non_loopback_peers_are_forbidden() {
        let response = handle_request(&get("/"), IpAddr::from([203, 0, 113, 5]), &inner());
        assert_eq!(response.status, FORBIDDEN);
    }

    #[test]
    fn post_is_not_allowed() {
        let response = handle_request(
            &Request::new("POST", "/"),
            IpAddr::from([127, 0, 0, 1]),
            &inner(),
        );
        assert_eq!(response.status, METHOD_NOT_ALLOWED);
        assert!(response.extra_headers.contains(&("Allow", "GET")));
    }

    #[test]
    fn dashboard_uses_shared_stats_sink() {
        let mut state = inner();
        state.stats = Some(Arc::new(StubStats));
        let response = handle_request(&get("/"), IpAddr::from([127, 0, 0, 1]), &state);
        let body = String::from_utf8(response.body).expect("HTML body is UTF-8");
        assert!(body.contains("Queries"));
        assert!(body.contains("4"));
    }
}
