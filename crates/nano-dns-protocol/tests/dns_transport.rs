//! Real UDP/TCP queries against a bound NanoDNS server and upstream stubs.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, Metadata, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType, rdata::A};
use ipnet::{IpNet, Ipv4Net};
use nano_dns_core::config::{Config, IpVersion, ListenerConfig, ResolverConfig, Upstream};
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
    let mut message = Message::query();
    message.metadata.id = id;
    message.add_query(Query::query(
        Name::from_ascii("example.com.").expect("valid name"),
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
    let port = free_udp_port();
    let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, port))
        .await
        .expect("bind upstream UDP");
    let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, port))
        .await
        .expect("bind upstream TCP");

    let _udp_task = tokio::spawn(async move {
        let mut buffer = [0u8; 4096];
        loop {
            let (len, src) = match udp.recv_from(&mut buffer).await {
                Ok(result) => result,
                Err(_) => break,
            };
            let response = upstream_response(&buffer[..len], truncated_udp);
            if udp.send_to(&response, src).await.is_err() {
                break;
            }
        }
    });

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
    assert_response(&buffer[..len], id, code, answers);
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
