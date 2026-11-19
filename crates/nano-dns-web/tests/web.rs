//! Real HTTP requests against a bound web dashboard.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nano_dns_core::blocker::{BlockListKind, BlockerControl, BlockerSnapshot};
use nano_dns_core::config::Config;
use nano_dns_core::model::{QueryEvent, StatsSnapshot};
use nano_dns_core::traits::StatsSink;
use nano_dns_web::WebServer;
use tokio::sync::oneshot;

fn free_port() -> u16 {
    let socket = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("free port");
    socket.local_addr().expect("local address").port()
}

struct StubStats;

impl StatsSink for StubStats {
    fn record(&self, _event: &QueryEvent) {}

    fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            total_queries: 11,
            blocked: 3,
            ..StatsSnapshot::default()
        }
    }
}

#[derive(Default)]
struct ControlState {
    enabled: bool,
    added: Vec<(BlockListKind, String)>,
    reloads: usize,
}

struct TestControl {
    state: Mutex<ControlState>,
}

impl BlockerControl for TestControl {
    fn snapshot(&self) -> BlockerSnapshot {
        BlockerSnapshot {
            enabled: self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .enabled,
            total_blocked: 5,
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

    fn add_domains(&self, kind: BlockListKind, text: &str) -> nano_dns_core::error::Result<usize> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut added = 0;
        for domain in text.lines().filter(|line| !line.trim().is_empty()) {
            state.added.push((kind, domain.trim().to_owned()));
            added += 1;
        }
        Ok(added)
    }

    fn remove_domain(
        &self,
        _kind: BlockListKind,
        _domain: &str,
    ) -> nano_dns_core::error::Result<bool> {
        Ok(true)
    }

    fn clear_domains(&self, _kind: BlockListKind) -> usize {
        0
    }

    fn reload_lists(&self) -> nano_dns_core::error::Result<usize> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .reloads += 1;
        Ok(2)
    }
}

fn config(port: u16) -> Config {
    let mut config = Config::default();
    config.web.enabled = true;
    config.web.listen = IpAddr::V4(Ipv4Addr::LOCALHOST);
    config.web.port = port;
    config
}

fn request(address: SocketAddr, raw: &str) -> (u16, HashMap<String, String>, String) {
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(2))
        .expect("web server must accept connections");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set read timeout");
    stream.write_all(raw.as_bytes()).expect("write request");
    stream.flush().expect("flush request");

    let mut response = Vec::new();
    stream.read_to_end(&mut response).expect("read response");
    let text = String::from_utf8(response).expect("response must be UTF-8");
    let (head, body) = text.split_once("\r\n\r\n").expect("response has headers");
    let mut lines = head.lines();
    let status = lines
        .next()
        .expect("status line")
        .split_whitespace()
        .nth(1)
        .expect("status code")
        .parse()
        .expect("numeric status");
    let headers = lines
        .filter_map(|line| line.split_once(": "))
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
        .collect();
    (status, headers, body.to_owned())
}

async fn start(
    config: &Config,
    stats: Option<Arc<dyn StatsSink>>,
) -> (
    SocketAddr,
    oneshot::Sender<()>,
    tokio::task::JoinHandle<nano_dns_core::error::Result<()>>,
) {
    let server = WebServer::bind(config, stats).await.expect("web must bind");
    let address = server.local_addr().expect("local address");
    let (tx, rx) = oneshot::channel::<()>();
    let task = tokio::spawn(async move {
        server
            .serve_with_signal(async move {
                let _ = rx.await;
            })
            .await
    });
    (address, tx, task)
}

async fn start_with_control(
    config: &Config,
    control: Arc<dyn BlockerControl>,
) -> (
    SocketAddr,
    oneshot::Sender<()>,
    tokio::task::JoinHandle<nano_dns_core::error::Result<()>>,
) {
    let server = WebServer::bind_with_blocker(config, None, Some(control))
        .await
        .expect("web must bind");
    let address = server.local_addr().expect("local address");
    let (tx, rx) = oneshot::channel::<()>();
    let task = tokio::spawn(async move {
        server
            .serve_with_signal(async move {
                let _ = rx.await;
            })
            .await
    });
    (address, tx, task)
}

async fn stop(
    tx: oneshot::Sender<()>,
    task: tokio::task::JoinHandle<nano_dns_core::error::Result<()>>,
) {
    let _ = tx.send(());
    let _ = task.await;
}

#[tokio::test(flavor = "multi_thread")]
async fn root_serves_dashboard() {
    let port = free_port();
    let (address, tx, task) = start(&config(port), None).await;

    let (status, headers, body) = request(address, "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert_eq!(status, 200);
    assert!(
        headers
            .get("Content-Type")
            .is_some_and(|value| value.starts_with("text/html"))
    );
    assert!(body.starts_with("<!DOCTYPE html>"));
    assert!(body.contains("NanoDNS"));

    stop(tx, task).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn dashboard_shows_shared_stats() {
    let port = free_port();
    let stats: Arc<dyn StatsSink> = Arc::new(StubStats);
    let (address, tx, task) = start(&config(port), Some(stats)).await;

    let (status, _, body) = request(address, "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert_eq!(status, 200);
    assert!(!body.contains("Statistics are disabled"));
    assert!(body.contains("11"));
    assert!(body.contains("3"));

    stop(tx, task).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn health_endpoint_is_plain_text() {
    let port = free_port();
    let (address, tx, task) = start(&config(port), None).await;

    let (status, headers, body) =
        request(address, "GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert_eq!(status, 200);
    assert!(
        headers
            .get("Content-Type")
            .is_some_and(|value| value.starts_with("text/plain"))
    );
    assert_eq!(body, "ok\n");

    stop(tx, task).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_path_returns_not_found() {
    let port = free_port();
    let (address, tx, task) = start(&config(port), None).await;

    let (status, _, _) = request(address, "GET /missing HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert_eq!(status, 404);

    stop(tx, task).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn post_is_rejected() {
    let port = free_port();
    let (address, tx, task) = start(&config(port), None).await;

    let (status, _, _) = request(address, "POST / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert_eq!(status, 405);

    stop(tx, task).await;
}

fn csrf_token(body: &str) -> String {
    let marker = "name=\"token\" value=\"";
    let start = body
        .find(marker)
        .expect("dashboard must render a token field")
        + marker.len();
    let rest = &body[start..];
    let end = rest.find('"').expect("token attribute must close");
    rest[..end].to_owned()
}

fn form_post(path: &str, fields: &[(&str, &str)]) -> String {
    let body = fields
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("&");
    format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn blocker_toggle_via_real_http_request() {
    let port = free_port();
    let control = Arc::new(TestControl {
        state: Mutex::new(ControlState {
            enabled: true,
            ..ControlState::default()
        }),
    });
    let (address, tx, task) = start_with_control(&config(port), control.clone()).await;

    let (_, _, dashboard) = request(address, "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    let token = csrf_token(&dashboard);
    assert!(dashboard.contains("Blocked"));
    assert!(dashboard.contains("5"));
    assert!(dashboard.contains("Disable filtering"));

    let raw = form_post(
        "/blocker/toggle",
        &[("token", &token), ("enabled", "false")],
    );
    let (status, headers, _) = request(address, &raw);
    assert_eq!(status, 303);
    assert_eq!(headers.get("Location").map(String::as_str), Some("/"));
    assert!(!control.is_enabled());

    let (_, _, dashboard) = request(address, "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert!(dashboard.contains("Enable filtering"));

    stop(tx, task).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn blocker_domain_management_via_real_http_request() {
    let port = free_port();
    let control = Arc::new(TestControl {
        state: Mutex::new(ControlState::default()),
    });
    let (address, tx, task) = start_with_control(&config(port), control.clone()).await;

    let (_, _, dashboard) = request(address, "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    let token = csrf_token(&dashboard);
    let raw = form_post(
        "/blocker/domains",
        &[
            ("token", &token),
            ("kind", "deny"),
            ("action", "add"),
            ("domains", "ads.example.com\ntrack.example.net"),
        ],
    );
    let (status, headers, _) = request(address, &raw);
    assert_eq!(status, 303);
    assert_eq!(headers.get("Location").map(String::as_str), Some("/"));

    let state = control
        .state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    assert_eq!(state.added.len(), 2);
    assert_eq!(state.added[0].0, BlockListKind::Deny);
    drop(state);

    stop(tx, task).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn blocker_control_rejects_wrong_token_over_http() {
    let port = free_port();
    let control = Arc::new(TestControl {
        state: Mutex::new(ControlState::default()),
    });
    let (address, tx, task) = start_with_control(&config(port), control.clone()).await;

    let raw = form_post(
        "/blocker/toggle",
        &[("token", "invalid"), ("enabled", "true")],
    );
    let (status, _, body) = request(address, &raw);
    assert_eq!(status, 403);
    assert_eq!(body, "Invalid control token");
    assert!(!control.is_enabled());

    stop(tx, task).await;
}
