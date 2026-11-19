//! Optional server-rendered web interface with blocker controls.

use std::collections::hash_map::RandomState;
use std::future::Future;
use std::hash::{BuildHasher, Hash, Hasher};
use std::net::{IpAddr, SocketAddr};
use std::process;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use nano_dns_core::blocker::{BlockListKind, BlockerControl};
use nano_dns_core::config::Config;
use nano_dns_core::error::Result;
use nano_dns_core::traits::StatsSink;
use nano_dns_http::{HttpServer, Request, Response};
use tracing::warn;

use crate::error::WebError;
use crate::page::{self, PageData};

const OK: u16 = 200;
const BAD_REQUEST: u16 = 400;
const FORBIDDEN: u16 = 403;
const NOT_FOUND: u16 = 404;
const METHOD_NOT_ALLOWED: u16 = 405;
const INTERNAL: u16 = 500;

const CONTROL_PATHS: [&str; 3] = ["/blocker/toggle", "/blocker/domains", "/blocker/reload"];

/// State shared with every accepted connection.
struct Inner {
    instance_name: String,
    resolver_mode: String,
    started_at: Instant,
    stats: Option<Arc<dyn StatsSink>>,
    blocker: Option<Arc<dyn BlockerControl>>,
    token: String,
}

/// A bound HTTP listener for the web dashboard.
pub struct WebServer {
    server: HttpServer<Inner>,
}

impl WebServer {
    /// Bind the configured web address without blocker controls.
    pub async fn bind(config: &Config, stats: Option<Arc<dyn StatsSink>>) -> Result<Self> {
        Self::bind_with_blocker(config, stats, None).await
    }

    /// Bind the configured web address and expose runtime blocker controls.
    pub async fn bind_with_blocker(
        config: &Config,
        stats: Option<Arc<dyn StatsSink>>,
        blocker: Option<Arc<dyn BlockerControl>>,
    ) -> Result<Self> {
        let address = SocketAddr::new(config.web.listen, config.web.port);
        let inner = Arc::new(Inner {
            instance_name: config.general.instance_name.clone(),
            resolver_mode: format!("{:?}", config.resolver.mode),
            started_at: Instant::now(),
            stats,
            blocker,
            token: new_token(),
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

/// Generate an unpredictable per-process token for state-changing requests.
/// `RandomState` seeds SipHash from OS entropy without adding a dependency.
fn new_token() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let mut hasher = RandomState::new().build_hasher();
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos() as u64)
        .hash(&mut hasher);
    process::id().hash(&mut hasher);
    COUNTER.fetch_add(1, Ordering::Relaxed).hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

/// The dashboard is loopback-only: `WebConfig` has no allow-list by design.
fn handle_request(request: &Request, peer: IpAddr, inner: &Inner) -> Response {
    if !peer.is_loopback() {
        warn!(%peer, "web request from non-loopback address");
        return Response::text(FORBIDDEN, "Forbidden");
    }

    let path = request.route_path();
    match (request.method.as_str(), path) {
        ("GET", "/") => dashboard(inner),
        ("GET", "/health") => Response::text(OK, "ok\n"),
        ("POST", path) if CONTROL_PATHS.contains(&path) => handle_control(request, path, inner),
        ("GET", path) if CONTROL_PATHS.contains(&path) => method_not_allowed("POST"),
        ("POST", "/" | "/health") => method_not_allowed("GET"),
        (_, "/" | "/health") => method_not_allowed("GET"),
        (_, path) if CONTROL_PATHS.contains(&path) => method_not_allowed("POST"),
        _ => Response::text(NOT_FOUND, "Not Found"),
    }
}

/// Render the dashboard from the current shared state.
fn dashboard(inner: &Inner) -> Response {
    let data = PageData {
        instance: &inner.instance_name,
        version: env!("CARGO_PKG_VERSION"),
        uptime_secs: inner.started_at.elapsed().as_secs(),
        resolver_mode: &inner.resolver_mode,
        stats: inner.stats.as_ref().map(|stats| stats.snapshot()),
        blocker: inner.blocker.as_ref().map(|blocker| blocker.snapshot()),
        token: &inner.token,
    };
    Response::html(OK, page::render(&data)).with_header("Cache-Control", "no-store")
}

/// Apply one blocker control submitted from the dashboard.
fn handle_control(request: &Request, path: &str, inner: &Inner) -> Response {
    let form = request.form();
    if form.get("token").map(String::as_str) != Some(inner.token.as_str()) {
        return Response::text(FORBIDDEN, "Invalid control token");
    }
    let Some(control) = inner.blocker.as_deref() else {
        return Response::text(NOT_FOUND, "Ad blocker is not available");
    };

    match path {
        "/blocker/toggle" => {
            let enabled = match form.get("enabled").map(String::as_str) {
                Some("true" | "on" | "1") => true,
                Some("false" | "off" | "0") => false,
                _ => return Response::text(BAD_REQUEST, "invalid enabled value"),
            };
            control.set_enabled(enabled);
            Response::redirect("/")
        }
        "/blocker/domains" => {
            let kind = match form.get("kind").map(String::as_str) {
                Some("allow") => BlockListKind::Allow,
                Some("deny") => BlockListKind::Deny,
                _ => return Response::text(BAD_REQUEST, "invalid rule kind"),
            };
            let text = form.get("domains").map_or("", String::as_str);
            match form.get("action").map(String::as_str) {
                Some("add") => match control.add_domains(kind, text) {
                    Ok(_) => Response::redirect("/"),
                    Err(error) => Response::text(INTERNAL, error.to_string()),
                },
                Some("remove") => {
                    for domain in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
                        if let Err(error) = control.remove_domain(kind, domain) {
                            return Response::text(INTERNAL, error.to_string());
                        }
                    }
                    Response::redirect("/")
                }
                Some("clear") => {
                    control.clear_domains(kind);
                    Response::redirect("/")
                }
                _ => Response::text(BAD_REQUEST, "invalid domain action"),
            }
        }
        "/blocker/reload" => match control.reload_lists() {
            Ok(_) => Response::redirect("/"),
            Err(error) => Response::text(INTERNAL, error.to_string()),
        },
        _ => Response::text(NOT_FOUND, "Not Found"),
    }
}

fn method_not_allowed(allow: &'static str) -> Response {
    Response::text(METHOD_NOT_ALLOWED, "Method Not Allowed").with_header("Allow", allow)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::time::Duration;

    use nano_dns_core::blocker::BlockerSnapshot;
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

    #[derive(Default)]
    struct StubState {
        enabled: bool,
        added: Vec<(BlockListKind, String)>,
        removed: Vec<(BlockListKind, String)>,
        cleared: usize,
        reloads: usize,
    }

    struct StubControl {
        state: Mutex<StubState>,
    }

    impl BlockerControl for StubControl {
        fn snapshot(&self) -> BlockerSnapshot {
            BlockerSnapshot {
                enabled: self
                    .state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .enabled,
                ..BlockerSnapshot::default()
            }
        }

        fn is_enabled(&self) -> bool {
            self.state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .enabled
        }

        fn set_enabled(&self, enabled: bool) {
            self.state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .enabled = enabled;
        }

        fn add_domains(&self, kind: BlockListKind, text: &str) -> Result<usize> {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let mut count = 0;
            for domain in text.lines() {
                if !domain.trim().is_empty() {
                    state.added.push((kind, domain.trim().to_owned()));
                    count += 1;
                }
            }
            Ok(count)
        }

        fn remove_domain(&self, kind: BlockListKind, domain: &str) -> Result<bool> {
            self.state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .removed
                .push((kind, domain.to_owned()));
            Ok(true)
        }

        fn clear_domains(&self, kind: BlockListKind) -> usize {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.added.retain(|(stored, _)| *stored != kind);
            state.cleared += 1;
            1
        }

        fn reload_lists(&self) -> Result<usize> {
            self.state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .reloads += 1;
            Ok(2)
        }
    }

    fn inner() -> Inner {
        Inner {
            instance_name: "NanoDNS".to_owned(),
            resolver_mode: format!("{:?}", ResolverMode::Forward),
            started_at: Instant::now() - Duration::from_secs(10),
            stats: None,
            blocker: None,
            token: "token123".to_owned(),
        }
    }

    fn get(path: &str) -> Request {
        Request::new("GET", path)
    }

    fn post(path: &str, fields: &[(&str, &str)]) -> Request {
        let mut request = Request::new("POST", path);
        request.body = fields
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>()
            .join("&")
            .into_bytes();
        request
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
        let response = handle_request(&post("/", &[]), IpAddr::from([127, 0, 0, 1]), &inner());
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

    #[test]
    fn dashboard_shows_blocker_controls_when_available() {
        let mut state = inner();
        state.blocker = Some(Arc::new(StubControl {
            state: Mutex::new(StubState::default()),
        }));
        let response = handle_request(&get("/"), IpAddr::from([127, 0, 0, 1]), &state);
        let body = String::from_utf8(response.body).expect("HTML body is UTF-8");
        assert!(body.contains("Ad blocker"));
        assert!(body.contains("Enable filtering"));
        assert!(body.contains("name=\"token\" value=\"token123\""));
    }

    #[test]
    fn control_requests_require_a_valid_token() {
        let response = handle_request(
            &post(
                "/blocker/toggle",
                &[("token", "wrong"), ("enabled", "false")],
            ),
            IpAddr::from([127, 0, 0, 1]),
            &inner(),
        );
        assert_eq!(response.status, FORBIDDEN);
    }

    #[test]
    fn toggle_changes_the_shared_blocker_state() {
        let control = Arc::new(StubControl {
            state: Mutex::new(StubState {
                enabled: true,
                ..StubState::default()
            }),
        });
        let mut state = inner();
        state.blocker = Some(control.clone());
        let response = handle_request(
            &post(
                "/blocker/toggle",
                &[("token", "token123"), ("enabled", "false")],
            ),
            IpAddr::from([127, 0, 0, 1]),
            &state,
        );
        assert_eq!(response.status, 303);
        assert!(response.extra_headers.contains(&("Location", "/")));
        assert!(!control.is_enabled());
    }

    #[test]
    fn domain_and_reload_endpoints_use_the_control() {
        let control = Arc::new(StubControl {
            state: Mutex::new(StubState::default()),
        });
        let mut state = inner();
        state.blocker = Some(control.clone());
        let peer = IpAddr::from([127, 0, 0, 1]);

        let added = handle_request(
            &post(
                "/blocker/domains",
                &[
                    ("token", "token123"),
                    ("kind", "deny"),
                    ("action", "add"),
                    ("domains", "ads.example.com"),
                ],
            ),
            peer,
            &state,
        );
        assert_eq!(added.status, 303);
        assert_eq!(
            control
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .added
                .len(),
            1
        );

        let reloaded = handle_request(
            &post("/blocker/reload", &[("token", "token123")]),
            peer,
            &state,
        );
        assert_eq!(reloaded.status, 303);
        assert_eq!(
            control
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .reloads,
            1
        );
    }

    #[test]
    fn controls_are_unavailable_without_a_blocker() {
        let response = handle_request(
            &post(
                "/blocker/toggle",
                &[("token", "token123"), ("enabled", "true")],
            ),
            IpAddr::from([127, 0, 0, 1]),
            &inner(),
        );
        assert_eq!(response.status, NOT_FOUND);
    }
}
