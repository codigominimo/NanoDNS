//! Real HTTP requests against a bound management API.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use nano_dns_api::ApiServer;
use nano_dns_core::config::{ApiConfig, Config};
use nano_dns_core::model::StatsSnapshot;
use nano_dns_core::traits::StatsSink;
use serde_json::Value;
use tokio::sync::oneshot;

fn free_port() -> u16 {
    let socket = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("free port");
    socket.local_addr().expect("local address").port()
}

struct StubStats;

impl StatsSink for StubStats {
    fn record(&self, _event: &nano_dns_core::model::QueryEvent) {}

    fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            total_queries: 7,
            allowed: 5,
            blocked: 2,
            ..StatsSnapshot::default()
        }
    }
}

fn config(port: u16, token: Option<&str>) -> Config {
    let mut config = Config::default();
    config.api = ApiConfig {
        enabled: true,
        listen: IpAddr::V4(Ipv4Addr::LOCALHOST),
        port,
        token: token.map(str::to_owned),
        allowed_networks: Vec::new(),
    };
    config
}

fn request(address: SocketAddr, raw: &str) -> (u16, Value) {
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(2))
        .expect("API must accept connections");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set read timeout");
    stream.write_all(raw.as_bytes()).expect("write request");
    stream.flush().expect("flush request");

    let mut response = Vec::new();
    stream.read_to_end(&mut response).expect("read response");
    let text = String::from_utf8(response).expect("response must be UTF-8");
    let (head, body) = text.split_once("\r\n\r\n").expect("response has headers");
    let status = head
        .split_whitespace()
        .nth(1)
        .expect("status code")
        .parse()
        .expect("numeric status");
    let body: Value = serde_json::from_str(body).expect("body must be JSON");
    (status, body)
}

async fn start(
    config: &Config,
    stats: Option<Arc<dyn StatsSink>>,
) -> (
    SocketAddr,
    oneshot::Sender<()>,
    tokio::task::JoinHandle<nano_dns_core::error::Result<()>>,
) {
    let server = ApiServer::bind(config, stats).await.expect("API must bind");
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
async fn status_endpoint_returns_ok() {
    let port = free_port();
    let (address, tx, task) = start(&config(port, None), None).await;

    let (status, body) = request(
        address,
        "GET /api/v1/status HTTP/1.1\r\nHost: localhost\r\n\r\n",
    );
    assert_eq!(status, 200);
    assert_eq!(body["status"], "ok");
    assert_eq!(body["statistics"], false);

    stop(tx, task).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn stats_endpoint_uses_shared_sink() {
    let port = free_port();
    let stats: Arc<dyn StatsSink> = Arc::new(StubStats);
    let (address, tx, task) = start(&config(port, None), Some(stats)).await;

    let (status, body) = request(
        address,
        "GET /api/v1/stats HTTP/1.1\r\nHost: localhost\r\n\r\n",
    );
    assert_eq!(status, 200);
    assert_eq!(body["total_queries"], 7);
    assert_eq!(body["blocked"], 2);

    stop(tx, task).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn token_is_required() {
    let port = free_port();
    let (address, tx, task) = start(&config(port, Some("secret")), None).await;

    let (status, _) = request(
        address,
        "GET /api/v1/status HTTP/1.1\r\nHost: localhost\r\n\r\n",
    );
    assert_eq!(status, 401);

    let (status, _) = request(
        address,
        "GET /api/v1/status HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer secret\r\n\r\n",
    );
    assert_eq!(status, 200);

    stop(tx, task).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn non_get_methods_are_rejected() {
    let port = free_port();
    let (address, tx, task) = start(&config(port, None), None).await;

    let (status, _) = request(
        address,
        "POST /api/v1/status HTTP/1.1\r\nHost: localhost\r\n\r\n",
    );
    assert_eq!(status, 405);

    stop(tx, task).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_endpoints_return_not_found() {
    let port = free_port();
    let (address, tx, task) = start(&config(port, None), None).await;

    let (status, _) = request(
        address,
        "GET /api/v1/unknown HTTP/1.1\r\nHost: localhost\r\n\r\n",
    );
    assert_eq!(status, 404);

    stop(tx, task).await;
}
