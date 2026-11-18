//! Real UDP/TCP queries against a bound NanoDNS server and upstream stubs.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, Metadata, OpCode, Query, ResponseCode};
use hickory_proto::rr::{
    Name, RData, Record, RecordType,
    rdata::{A, NS},
};
use ipnet::{IpNet, Ipv4Net};
use nano_dns_core::config::{
    BlockResponse, Config, IpVersion, ListenerConfig, ResolverConfig, ResolverMode, Upstream,
};
use nano_dns_protocol::DnsServer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::oneshot;
use tokio::time::timeout;

fn free_udp_port() -> u16 {
    let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("free UDP port");
    socket.local_addr().expect("UDP local address").port()
}

fn config(udp_port: u16, tcp_port: u16, upstream_port: u16, tcp_only: bool) -> Config {
    let mut config = Config::default();
    config.listeners.ip_version = IpVersion::V4;
    config.listeners.entries = vec![ListenerConfig {
        address: IpAddr::V4(Ipv4Addr::LOCALHOST),
        port_udp: udp_port,
        port_tcp: tcp_port,
        dot: false,
        doh: false,
    }];
    config.listeners.allowed_networks = vec![IpNet::V4(Ipv4Net::from(Ipv4Addr::LOCALHOST))];
    config.resolver = ResolverConfig {
        upstreams: vec![Upstream {
            address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: upstream_port,
            tcp: tcp_only,
        }],
        timeout_ms: 1_000,
        retries: 0,
        ..ResolverConfig::default()
    };
    config
}

fn query(id: u16) -> Vec<u8> {
    named_query(id, "example.com.")
}

fn named_query(id: u16, name: &str) -> Vec<u8> {
    let mut message = Message::query();
    message.metadata.id = id;
    message.add_query(Query::query(
        Name::from_ascii(name).expect("valid name"),
        RecordType::A,
    ));
    message.to_vec().expect("query must encode")
}

fn upstream_response(query_bytes: &[u8], truncated: bool) -> Vec<u8> {
    let request = Message::from_vec(query_bytes).expect("upstream must decode query");
    let mut response = Message::response(request.metadata.id, OpCode::Query);
    response.metadata = Metadata::response_from_request(&request.metadata);
    response.metadata.recursion_available = true;
    response.metadata.truncation = truncated;
    response.add_queries(request.queries.iter().cloned());

    if !truncated {
        response.add_answer(Record::from_rdata(
            request.queries[0].name().clone(),
            60,
            RData::A(A::new(127, 0, 0, 1)),
        ));
    }

    response.to_vec().expect("upstream response must encode")
}

/// Start UDP and TCP upstream stubs on the same port. Each stub answers every
/// query it receives until its socket is closed at the end of the test.
async fn spawn_upstream(truncated_udp: bool) -> u16 {
    spawn_upstream_counted(truncated_udp, Arc::new(AtomicUsize::new(0))).await
}

/// Variant of [`spawn_upstream`] that counts queries received over either
/// transport, so tests can assert whether a lookup reached the upstream.
async fn spawn_upstream_counted(truncated_udp: bool, queries: Arc<AtomicUsize>) -> u16 {
    let port = free_udp_port();
    let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, port))
        .await
        .expect("bind upstream UDP");
    let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, port))
        .await
        .expect("bind upstream TCP");

    let udp_queries = Arc::clone(&queries);
    let _udp_task = tokio::spawn(async move {
        let mut buffer = [0u8; 4096];
        loop {
            let (len, src) = match udp.recv_from(&mut buffer).await {
                Ok(result) => result,
                Err(_) => break,
            };
            udp_queries.fetch_add(1, Ordering::SeqCst);
            let response = upstream_response(&buffer[..len], truncated_udp);
            if udp.send_to(&response, src).await.is_err() {
                break;
            }
        }
    });

    let tcp_queries = Arc::clone(&queries);
    let _tcp_task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = match tcp.accept().await {
                Ok(result) => result,
                Err(_) => break,
            };
            let mut length = [0u8; 2];
            if stream.read_exact(&mut length).await.is_err() {
                continue;
            }
            let mut request = vec![0u8; usize::from(u16::from_be_bytes(length))];
            if stream.read_exact(&mut request).await.is_err() {
                continue;
            }
            tcp_queries.fetch_add(1, Ordering::SeqCst);
            let response = upstream_response(&request, false);
            if let Ok(length) = u16::try_from(response.len()) {
                let _ = stream.write_all(&length.to_be_bytes()).await;
                let _ = stream.write_all(&response).await;
            }
        }
    });

    port
}

fn assert_response(bytes: &[u8], id: u16, code: ResponseCode, answers: usize) {
    let response = Message::from_vec(bytes).expect("response must decode");
    assert_eq!(response.metadata.id, id);
    assert_eq!(response.metadata.message_type, MessageType::Response);
    assert_eq!(response.metadata.response_code, code);
    assert_eq!(response.answers.len(), answers);
}

async fn udp_query(port: u16, packet: Vec<u8>, id: u16, code: ResponseCode, answers: usize) {
    let bytes = udp_query_raw(port, packet).await;
    assert_response(&bytes, id, code, answers);
}

async fn udp_query_raw(port: u16, packet: Vec<u8>) -> Vec<u8> {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("client UDP socket");
    socket
        .send_to(&packet, SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
        .await
        .expect("send UDP query");

    let mut buffer = [0u8; 2048];
    let (len, _) = timeout(Duration::from_secs(2), socket.recv_from(&mut buffer))
        .await
        .expect("UDP query timed out")
        .expect("receive UDP response");
    buffer[..len].to_vec()
}

async fn tcp_query(port: u16, packet: Vec<u8>, id: u16, code: ResponseCode, answers: usize) {
    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
        .await
        .expect("connect TCP");

    let length = u16::try_from(packet.len()).expect("query fits DNS length prefix");
    stream
        .write_all(&length.to_be_bytes())
        .await
        .expect("write TCP length");
    stream.write_all(&packet).await.expect("write TCP query");

    let mut length = [0u8; 2];
    timeout(Duration::from_secs(2), stream.read_exact(&mut length))
        .await
        .expect("TCP response timed out")
        .expect("read TCP length");
    let mut buffer = vec![0u8; usize::from(u16::from_be_bytes(length))];
    timeout(Duration::from_secs(2), stream.read_exact(&mut buffer))
        .await
        .expect("TCP body timed out")
        .expect("read TCP response");
    assert_response(&buffer, id, code, answers);
}

async fn start_server(
    config: &Config,
) -> (
    oneshot::Sender<()>,
    tokio::task::JoinHandle<nano_dns_core::error::Result<()>>,
) {
    let mut server = DnsServer::bind(config).await.expect("server must bind");
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let task = tokio::spawn(async move {
        server
            .serve_with_signal(async move {
                let _ = shutdown_rx.await;
            })
            .await
    });
    (shutdown_tx, task)
}

async fn stop_server(
    shutdown_tx: oneshot::Sender<()>,
    task: tokio::task::JoinHandle<nano_dns_core::error::Result<()>>,
) {
    let _ = shutdown_tx.send(());
    timeout(Duration::from_secs(2), task)
        .await
        .expect("server shutdown timed out")
        .expect("server task must join")
        .expect("server must shut down cleanly");
}

#[tokio::test]
async fn udp_and_tcp_queries_are_forwarded() {
    let upstream_port = spawn_upstream(false).await;
    let udp_port = free_udp_port();
    let tcp_port = free_udp_port();
    let config = config(udp_port, tcp_port, upstream_port, false);
    let (shutdown_tx, task) = start_server(&config).await;

    udp_query(udp_port, query(1), 1, ResponseCode::NoError, 1).await;
    tcp_query(tcp_port, query(2), 2, ResponseCode::NoError, 1).await;

    stop_server(shutdown_tx, task).await;
}

#[tokio::test]
async fn tcp_only_upstream_is_used() {
    let upstream_port = spawn_upstream(false).await;
    let udp_port = free_udp_port();
    let tcp_port = free_udp_port();
    let config = config(udp_port, tcp_port, upstream_port, true);
    let (shutdown_tx, task) = start_server(&config).await;

    tcp_query(tcp_port, query(3), 3, ResponseCode::NoError, 1).await;

    stop_server(shutdown_tx, task).await;
}

#[tokio::test]
async fn truncated_udp_answer_is_retried_over_tcp() {
    let upstream_port = spawn_upstream(true).await;
    let udp_port = free_udp_port();
    let tcp_port = free_udp_port();
    let config = config(udp_port, tcp_port, upstream_port, false);
    let (shutdown_tx, task) = start_server(&config).await;

    udp_query(udp_port, query(4), 4, ResponseCode::NoError, 1).await;

    stop_server(shutdown_tx, task).await;
}

#[tokio::test]
async fn oversized_udp_query_receives_formerr() {
    let upstream_port = spawn_upstream(false).await;
    let udp_port = free_udp_port();
    let tcp_port = free_udp_port();
    let mut config = config(udp_port, tcp_port, upstream_port, false);
    config.listeners.max_packet_bytes = 512;
    let (shutdown_tx, task) = start_server(&config).await;

    let mut packet = query(5);
    packet.resize(700, 0);
    udp_query(udp_port, packet, 5, ResponseCode::FormErr, 0).await;

    stop_server(shutdown_tx, task).await;
}

#[tokio::test]
async fn unreachable_upstream_receives_servfail() {
    let upstream_port = free_udp_port();
    let udp_port = free_udp_port();
    let tcp_port = free_udp_port();
    let config = config(udp_port, tcp_port, upstream_port, false);
    let (shutdown_tx, task) = start_server(&config).await;

    udp_query(udp_port, query(6), 6, ResponseCode::ServFail, 0).await;

    stop_server(shutdown_tx, task).await;
}

#[tokio::test]
async fn repeated_queries_are_served_from_cache() {
    let counter = Arc::new(AtomicUsize::new(0));
    let upstream_port = spawn_upstream_counted(false, Arc::clone(&counter)).await;
    let udp_port = free_udp_port();
    let tcp_port = free_udp_port();
    let config = config(udp_port, tcp_port, upstream_port, false);
    let (shutdown_tx, task) = start_server(&config).await;

    udp_query(udp_port, query(7), 7, ResponseCode::NoError, 1).await;
    tcp_query(tcp_port, query(8), 8, ResponseCode::NoError, 1).await;

    assert_eq!(counter.load(Ordering::SeqCst), 1);
    stop_server(shutdown_tx, task).await;
}

#[tokio::test]
async fn disabled_cache_forwards_every_query() {
    let counter = Arc::new(AtomicUsize::new(0));
    let upstream_port = spawn_upstream_counted(false, Arc::clone(&counter)).await;
    let udp_port = free_udp_port();
    let tcp_port = free_udp_port();
    let mut config = config(udp_port, tcp_port, upstream_port, false);
    config.dns_cache.enabled = false;
    let (shutdown_tx, task) = start_server(&config).await;

    udp_query(udp_port, query(9), 9, ResponseCode::NoError, 1).await;
    udp_query(udp_port, query(10), 10, ResponseCode::NoError, 1).await;

    assert_eq!(counter.load(Ordering::SeqCst), 2);
    stop_server(shutdown_tx, task).await;
}

#[tokio::test]
async fn blocked_domain_is_answered_without_querying_upstream() {
    let counter = Arc::new(AtomicUsize::new(0));
    let upstream_port = spawn_upstream_counted(false, Arc::clone(&counter)).await;
    let udp_port = free_udp_port();
    let tcp_port = free_udp_port();
    let mut config = config(udp_port, tcp_port, upstream_port, false);
    config.blocker.denylist = vec!["blocked.example".to_owned()];
    let (shutdown_tx, task) = start_server(&config).await;

    udp_query(
        udp_port,
        named_query(11, "www.blocked.example."),
        11,
        ResponseCode::NXDomain,
        0,
    )
    .await;
    assert_eq!(counter.load(Ordering::SeqCst), 0);

    udp_query(udp_port, query(12), 12, ResponseCode::NoError, 1).await;
    assert_eq!(counter.load(Ordering::SeqCst), 1);

    stop_server(shutdown_tx, task).await;
}

#[tokio::test]
async fn nodata_and_sinkhole_responses_are_configurable() {
    let upstream_port = spawn_upstream(false).await;
    let udp_port = free_udp_port();
    let tcp_port = free_udp_port();
    let mut nodata_config = config(udp_port, tcp_port, upstream_port, false);
    nodata_config.blocker.block_response = BlockResponse::Nodata;
    nodata_config.blocker.denylist = vec!["empty.example".to_owned()];
    let (shutdown_tx, task) = start_server(&nodata_config).await;

    udp_query(
        udp_port,
        named_query(13, "empty.example."),
        13,
        ResponseCode::NoError,
        0,
    )
    .await;

    stop_server(shutdown_tx, task).await;

    let udp_port = free_udp_port();
    let tcp_port = free_udp_port();
    let mut sinkhole_config = config(udp_port, tcp_port, upstream_port, false);
    sinkhole_config.blocker.block_response = BlockResponse::Sinkhole;
    sinkhole_config.blocker.denylist = vec!["sinkhole.example".to_owned()];
    sinkhole_config.blocker.sinkhole_v4 = Ipv4Addr::new(192, 0, 2, 1);
    let (shutdown_tx, task) = start_server(&sinkhole_config).await;

    let bytes = udp_query_raw(udp_port, named_query(14, "sinkhole.example.")).await;
    let response = Message::from_vec(&bytes).expect("response must decode");
    assert_eq!(response.metadata.id, 14);
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert_eq!(response.answers.len(), 1);
    match &response.answers[0].data {
        RData::A(address) => {
            assert_eq!(
                Ipv4Addr::from(*address),
                sinkhole_config.blocker.sinkhole_v4
            )
        }
        other => panic!("unexpected sinkhole record: {other:?}"),
    }

    stop_server(shutdown_tx, task).await;
}

#[cfg(feature = "recursive")]
async fn spawn_recursive_stub(
    address: Ipv4Addr,
    port: u16,
    handler: impl Fn(Message) -> Message + Send + 'static,
) {
    let socket = UdpSocket::bind((address, port))
        .await
        .expect("bind recursive stub");
    tokio::spawn(async move {
        let mut buffer = [0u8; 4096];
        loop {
            let (len, src) = match socket.recv_from(&mut buffer).await {
                Ok(result) => result,
                Err(_) => break,
            };
            let request = match Message::from_vec(&buffer[..len]) {
                Ok(request) => request,
                Err(_) => continue,
            };
            if let Ok(bytes) = handler(request).to_vec() {
                let _ = socket.send_to(&bytes, src).await;
            }
        }
    });
}

#[cfg(feature = "recursive")]
#[tokio::test]
async fn recursive_mode_resolves_from_root_hints() {
    let root_port = free_udp_port();
    spawn_recursive_stub(Ipv4Addr::LOCALHOST, root_port, |request| {
        let mut response = Message::response(request.metadata.id, OpCode::Query);
        response.metadata = Metadata::response_from_request(&request.metadata);
        response.add_queries(request.queries.iter().cloned());
        response.add_authority(Record::from_rdata(
            Name::from_ascii("example.com.").expect("valid zone"),
            300,
            RData::NS(NS(
                Name::from_ascii("ns.example.com.").expect("valid server")
            )),
        ));
        response.add_additional(Record::from_rdata(
            Name::from_ascii("ns.example.com.").expect("valid server"),
            300,
            RData::A(A::from(Ipv4Addr::new(127, 0, 0, 2))),
        ));
        response
    })
    .await;
    spawn_recursive_stub(Ipv4Addr::new(127, 0, 0, 2), root_port, |request| {
        let mut response = Message::response(request.metadata.id, OpCode::Query);
        response.metadata = Metadata::response_from_request(&request.metadata);
        response.metadata.authoritative = true;
        response.add_queries(request.queries.iter().cloned());
        response.add_answer(Record::from_rdata(
            request.queries[0].name().clone(),
            120,
            RData::A(A::new(192, 0, 2, 30)),
        ));
        response
    })
    .await;

    let udp_port = free_udp_port();
    let tcp_port = free_udp_port();
    let mut server_config = config(udp_port, tcp_port, root_port, false);
    server_config.resolver.mode = ResolverMode::Recursive;
    server_config.resolver.upstreams.clear();
    server_config.resolver.root_hints = vec![IpAddr::V4(Ipv4Addr::LOCALHOST)];
    server_config.resolver.root_port = root_port;
    let (shutdown_tx, task) = start_server(&server_config).await;

    udp_query(udp_port, query(15), 15, ResponseCode::NoError, 1).await;

    stop_server(shutdown_tx, task).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn sqlite_history_records_completed_queries() {
    static NEXT_DB: AtomicU64 = AtomicU64::new(0);

    let upstream_port = spawn_upstream(false).await;
    let udp_port = free_udp_port();
    let tcp_port = free_udp_port();
    let database = std::env::temp_dir().join(format!(
        "nano-dns-integration-{}-{}.sqlite3",
        std::process::id(),
        NEXT_DB.fetch_add(1, Ordering::Relaxed)
    ));

    let mut server_config = config(udp_port, tcp_port, upstream_port, false);
    server_config.storage.enabled = true;
    server_config.storage.history = true;
    server_config.storage.path = database.clone();
    let (shutdown_tx, task) = start_server(&server_config).await;

    udp_query(udp_port, query(16), 16, ResponseCode::NoError, 1).await;
    stop_server(shutdown_tx, task).await;

    let connection = rusqlite::Connection::open(&database).expect("history database must open");
    let count: i64 = connection
        .query_row("SELECT COUNT(*) FROM query_history", [], |row| row.get(0))
        .expect("history table must exist");
    assert_eq!(count, 1);

    let (domain, decision, response_code): (String, String, i64) = connection
        .query_row(
            "SELECT domain, decision, response_code FROM query_history",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("query event must be stored");
    assert_eq!(domain, "example.com.");
    assert_eq!(decision, "allow");
    assert_eq!(response_code, 0);
    drop(connection);

    let _ = std::fs::remove_file(&database);
    let _ = std::fs::remove_file(database.with_extension("sqlite3-wal"));
    let _ = std::fs::remove_file(database.with_extension("sqlite3-shm"));
}

#[cfg(feature = "statistics")]
#[tokio::test]
async fn statistics_records_completed_queries() {
    let upstream_port = spawn_upstream(false).await;
    let udp_port = free_udp_port();
    let tcp_port = free_udp_port();

    let mut server_config = config(udp_port, tcp_port, upstream_port, false);
    server_config.stats.enabled = true;
    server_config.stats.retention_secs = 60;
    let mut server = DnsServer::bind(&server_config)
        .await
        .expect("server must bind");

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let client = tokio::spawn(async move {
        udp_query(udp_port, query(17), 17, ResponseCode::NoError, 1).await;
        let _ = shutdown_tx.send(());
    });

    server
        .serve_with_signal(async move {
            let _ = shutdown_rx.await;
        })
        .await
        .expect("server must serve");
    client.await.expect("client task must finish");

    let snapshot = server.stats_snapshot().expect("statistics must be enabled");
    assert_eq!(snapshot.total_queries, 1);
    assert_eq!(snapshot.allowed, 1);
    assert_eq!(snapshot.blocked, 0);
    assert_eq!(snapshot.transports.get("udp"), Some(&1));
    assert_eq!(snapshot.top_domains[0].0, "example.com.");
}
