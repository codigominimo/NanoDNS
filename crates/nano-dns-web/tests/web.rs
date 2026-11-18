//! Real HTTP requests against a bound web dashboard.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

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

fn config(port: u16) -> Config {
    let mut config = Config::default();
    config.web.enabled = true;
    config.web.listen = IpAddr::V4(Ipv4Addr::LOCALHOST);
    config.web.port = port;
    config
}

fn request(address: SocketAddr, raw: &str) -> (u16, String, String) {
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
    let content_type = lines
        .find_map(|line| line.strip_prefix("Content-Type: "))
        .unwrap_or_default()
        .to_owned();
    (status, content_type, body.to_owned())
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

    let (status, content_type, body) =
        request(address, "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert_eq!(status, 200);
    assert!(content_type.starts_with("text/html"));
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

    let (status, content_type, body) =
        request(address, "GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert_eq!(status, 200);
    assert!(content_type.starts_with("text/plain"));
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
