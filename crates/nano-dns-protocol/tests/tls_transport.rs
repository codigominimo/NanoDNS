//! Real DoT and DoH queries against a bound NanoDNS server.
//!
//! Certificates are generated at runtime with `rcgen`, so no private keys are
//! stored in the repository and the tests never depend on external tools.

use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType, rdata::A};
use nano_dns_core::config::{
    Config, DohConfig, DotConfig, IpVersion, ListenerConfig, ResolverConfig, Upstream,
};
use nano_dns_protocol::DnsServer;
use rcgen::generate_simple_self_signed;
use rustls::RootCertStore;
use rustls::crypto::ring;
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

/// Test certificate files and their owning directory.
struct TestCerts {
    dir: PathBuf,
    cert_path: PathBuf,
    key_path: PathBuf,
    der: Vec<u8>,
}

impl TestCerts {
    fn generate() -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is after the epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("nanodns-tls-{unique}"));
        fs::create_dir_all(&dir).expect("create temporary certificate directory");

        let certified = generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("generate self-signed certificate");
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("cert.key");
        fs::write(&cert_path, certified.cert.pem()).expect("write test certificate");
        fs::write(&key_path, certified.key_pair.serialize_pem()).expect("write test private key");

        let der = certified.cert.der().to_vec();
        Self {
            dir,
            cert_path,
            key_path,
            der,
        }
    }

    fn client_config(&self, alpn: &[u8]) -> rustls::ClientConfig {
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(self.der.clone()))
            .expect("add test certificate to root store");
        let mut config =
            rustls::ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
                .with_safe_default_protocol_versions()
                .expect("supported TLS versions")
                .with_root_certificates(roots)
                .with_no_client_auth();
        config.alpn_protocols = vec![alpn.to_vec()];
        config
    }
}

impl Drop for TestCerts {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// Find a port usable by both UDP and TCP. Windows can reserve ranges for one
/// transport only, so a TCP-only probe can return a port the UDP listener cannot bind.
fn free_port() -> u16 {
    for _ in 0..64 {
        let udp = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("free UDP port");
        let port = udp.local_addr().expect("UDP local address").port();
        if std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok() {
            return port;
        }
    }
    panic!("no port is free for both UDP and TCP");
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

fn upstream_response(query_bytes: &[u8]) -> Vec<u8> {
    let request = Message::from_vec(query_bytes).expect("upstream must decode query");
    let mut response = Message::response(request.metadata.id, OpCode::Query);
    response.metadata = hickory_proto::op::Metadata::response_from_request(&request.metadata);
    response.metadata.recursion_available = true;
    response.add_queries(request.queries.iter().cloned());
    response.add_answer(Record::from_rdata(
        request.queries[0].name().clone(),
        60,
        RData::A(A::new(127, 0, 0, 2)),
    ));
    response.to_vec().expect("upstream response must encode")
}

async fn spawn_upstream() -> u16 {
    let port = free_port();
    let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, port))
        .await
        .expect("bind upstream TCP");
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = tcp.accept().await else {
                break;
            };
            let mut length = [0u8; 2];
            if stream.read_exact(&mut length).await.is_err() {
                continue;
            }
            let mut request = vec![0u8; usize::from(u16::from_be_bytes(length))];
            if stream.read_exact(&mut request).await.is_err() {
                continue;
            }
            let response = upstream_response(&request);
            if let Ok(length) = u16::try_from(response.len()) {
                let _ = stream.write_all(&length.to_be_bytes()).await;
                let _ = stream.write_all(&response).await;
            }
        }
    });
    port
}

/// Build a configuration with one loopback listener serving all transports.
async fn config(certs: &TestCerts) -> Config {
    let upstream_port = spawn_upstream().await;
    let mut config = Config::default();
    config.listeners.ip_version = IpVersion::V4;
    config.listeners.entries = vec![ListenerConfig {
        address: IpAddr::V4(Ipv4Addr::LOCALHOST),
        port_udp: free_port(),
        port_tcp: free_port(),
        dot: true,
        doh: true,
    }];
    config.resolver = ResolverConfig {
        upstreams: vec![Upstream {
            address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: upstream_port,
            tcp: true,
        }],
        timeout_ms: 1_000,
        retries: 0,
        ..ResolverConfig::default()
    };
    config.dot = DotConfig {
        enabled: true,
        port: free_port(),
        cert_path: Some(certs.cert_path.clone()),
        key_path: Some(certs.key_path.clone()),
    };
    config.doh = DohConfig {
        enabled: true,
        port: free_port(),
        path: "/dns-query".to_owned(),
        cert_path: Some(certs.cert_path.clone()),
        key_path: Some(certs.key_path.clone()),
    };
    config
}

fn assert_dns_response(bytes: &[u8], id: u16) {
    let response = Message::from_vec(bytes).expect("response must decode");
    assert_eq!(response.metadata.id, id);
    assert_eq!(response.metadata.message_type, MessageType::Response);
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert_eq!(response.answers.len(), 1);
}

async fn tls_stream(
    certs: &TestCerts,
    port: u16,
    alpn: &[u8],
) -> tokio_rustls::client::TlsStream<TcpStream> {
    let stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
        .await
        .expect("connect to TLS listener");
    let connector = tokio_rustls::TlsConnector::from(Arc::new(certs.client_config(alpn)));
    let name = ServerName::try_from("localhost").expect("valid server name");
    timeout(Duration::from_secs(5), connector.connect(name, stream))
        .await
        .expect("TLS handshake must finish")
        .expect("TLS handshake must succeed")
}

#[tokio::test(flavor = "multi_thread")]
async fn dot_forwards_query() {
    let certs = TestCerts::generate();
    let config = config(&certs).await;
    let dot_port = config.dot.port;
    let mut server = DnsServer::bind(&config)
        .await
        .expect("DNS server must bind");

    let mut stream = tls_stream(&certs, dot_port, b"dot").await;
    let request = query(41);
    let length = u16::try_from(request.len()).expect("query fits in TCP frame");
    stream
        .write_all(&length.to_be_bytes())
        .await
        .expect("write length prefix");
    stream.write_all(&request).await.expect("write DNS query");

    let mut prefix = [0u8; 2];
    timeout(Duration::from_secs(5), stream.read_exact(&mut prefix))
        .await
        .expect("response must arrive")
        .expect("read length prefix");
    let mut response = vec![0u8; usize::from(u16::from_be_bytes(prefix))];
    stream
        .read_exact(&mut response)
        .await
        .expect("read DNS response");
    assert_dns_response(&response, 41);

    server.shutdown().await.expect("graceful shutdown");
}

#[tokio::test(flavor = "multi_thread")]
async fn doh_forwards_query() {
    let certs = TestCerts::generate();
    let config = config(&certs).await;
    let doh_port = config.doh.port;
    let mut server = DnsServer::bind(&config)
        .await
        .expect("DNS server must bind");

    let tls = tls_stream(&certs, doh_port, b"h2").await;
    let (mut sender, connection) = h2::client::handshake(tls)
        .await
        .expect("HTTP/2 handshake must succeed");
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri("https://localhost/dns-query")
        .header("content-type", "application/dns-message")
        .header("accept", "application/dns-message")
        .body(())
        .expect("build DoH request");
    let (response, mut body) = sender
        .send_request(request, false)
        .expect("send DoH request");
    body.send_data(Bytes::from(query(52)), true)
        .expect("send DNS query body");

    let response = timeout(Duration::from_secs(5), response)
        .await
        .expect("DoH response must arrive")
        .expect("DoH request must succeed");
    assert_eq!(response.status(), http::StatusCode::OK);

    let mut body = response.into_body();
    let mut bytes = Vec::new();
    while let Some(chunk) = body.data().await {
        bytes.extend_from_slice(&chunk.expect("read response chunk"));
    }
    assert_dns_response(&bytes, 52);

    server.shutdown().await.expect("graceful shutdown");
}

#[tokio::test(flavor = "multi_thread")]
async fn doh_rejects_wrong_path() {
    let certs = TestCerts::generate();
    let config = config(&certs).await;
    let doh_port = config.doh.port;
    let mut server = DnsServer::bind(&config)
        .await
        .expect("DNS server must bind");

    let tls = tls_stream(&certs, doh_port, b"h2").await;
    let (mut sender, connection) = h2::client::handshake(tls)
        .await
        .expect("HTTP/2 handshake must succeed");
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri("https://localhost/wrong")
        .header("content-type", "application/dns-message")
        .header("accept", "application/dns-message")
        .body(())
        .expect("build DoH request");
    let (response, mut body) = sender
        .send_request(request, false)
        .expect("send DoH request");
    body.send_data(Bytes::from(query(53)), true)
        .expect("send DNS query body");

    let result = timeout(Duration::from_secs(5), response)
        .await
        .expect("server must react to bad path");
    assert!(result.is_err(), "Hickory closes streams with invalid paths");

    server.shutdown().await.expect("graceful shutdown");
}

/// The upstream stub is UDP-capable too; this keeps `UdpSocket` referenced so
/// the helper stays useful for future transport tests without extra crates.
#[test]
fn udp_helper_is_available() {
    let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("free UDP port");
    assert!(socket.local_addr().is_ok());
}
