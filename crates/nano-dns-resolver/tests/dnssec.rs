//! DNSSEC validation tests using a local authoritative stub on an ephemeral port.

#![cfg(feature = "dnssec")]

use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hickory_proto::dnssec::crypto::Ed25519SigningKey;
use hickory_proto::dnssec::rdata::{DNSKEY, DNSSECRData, RRSIG, SigInput};
use hickory_proto::dnssec::{DnssecSigner, SigningKey, TBS, TrustAnchors};
use hickory_proto::op::{Message, OpCode, Query};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType, SerialNumber};
use nano_dns_core::config::{ResolverConfig, ResolverMode, Upstream};
use nano_dns_core::model::ClientIdentity;
use nano_dns_core::model::{DnsQuery, QueryContext, Transport};
use nano_dns_core::traits::Resolver;
use nano_dns_resolver::DnssecResolver;
use tokio::net::UdpSocket;

#[derive(Clone, Copy, PartialEq, Eq)]
enum StubMode {
    Signed,
    Unsigned,
}

fn signing_key() -> Ed25519SigningKey {
    let pkcs8 = Ed25519SigningKey::generate_pkcs8().expect("key generation");
    Ed25519SigningKey::from_pkcs8(&pkcs8).expect("key decoding")
}

fn dnskey_record(key: &Ed25519SigningKey) -> Record {
    let public = key.to_public_key().expect("public key");
    Record::from_rdata(
        Name::root(),
        3600,
        RData::DNSSEC(DNSSECRData::DNSKEY(DNSKEY::from_key(&public))),
    )
}

fn rrsig_record(
    name: &Name,
    record_type: RecordType,
    signer: &DnssecSigner,
    record: &Record,
) -> Record {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32;
    let input = SigInput {
        type_covered: record_type,
        algorithm: signer.key().algorithm(),
        num_labels: name.num_labels(),
        original_ttl: record.ttl,
        sig_expiration: SerialNumber::new(now + 3600),
        sig_inception: SerialNumber::new(now.saturating_sub(60)),
        key_tag: signer.calculate_key_tag().expect("key tag"),
        signer_name: signer.signer_name().clone(),
    };
    let tbs = TBS::from_input(
        name,
        DNSClass::IN,
        &input,
        std::slice::from_ref(record).iter(),
    )
    .expect("TBS serialization");
    let signature = signer.sign(&tbs).expect("RRSIG signature");
    Record::from_rdata(
        name.clone(),
        record.ttl,
        RData::DNSSEC(DNSSECRData::RRSIG(RRSIG::from_sig(input, signature))),
    )
}

async fn spawn_stub(
    mode: StubMode,
    label: &str,
) -> (SocketAddr, PathBuf, tokio::task::JoinHandle<()>) {
    let key = signing_key();
    let anchor = write_anchor(&key, label);
    let public = key.to_public_key().expect("public key");
    let dnskey = DNSKEY::from_key(&public);
    let key_record = Record::from_rdata(
        Name::root(),
        3600,
        RData::DNSSEC(DNSSECRData::DNSKEY(dnskey.clone())),
    );
    let signer = DnssecSigner::new(
        dnskey,
        Box::new(key),
        Name::root(),
        Duration::from_secs(3600),
    );

    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("stub socket");
    let address = socket.local_addr().expect("stub address");
    let task = tokio::spawn(async move {
        let mut buffer = vec![0u8; 4096];
        loop {
            let Ok((length, peer)) = socket.recv_from(&mut buffer).await else {
                break;
            };
            let Ok(request) = Message::from_vec(&buffer[..length]) else {
                continue;
            };
            let Some(query) = request.queries.first().cloned() else {
                continue;
            };

            let mut response = Message::response(request.metadata.id, OpCode::Query);
            response.add_query(query.clone());
            response.edns = request.edns.clone();
            response.metadata.authoritative = true;
            response.metadata.recursion_available = true;

            if query.query_type() == RecordType::DNSKEY && query.name().is_root() {
                response.add_answer(key_record.clone());
            } else if query.query_type() == RecordType::A {
                let name = query.name().clone();
                let answer =
                    Record::from_rdata(name.clone(), 60, RData::A(A::new(203, 0, 113, 10)));
                response.add_answer(answer.clone());
                if mode == StubMode::Signed {
                    response.add_answer(rrsig_record(&name, RecordType::A, &signer, &answer));
                }
            }

            if let Ok(bytes) = response.to_vec() {
                let _ = socket.send_to(&bytes, peer).await;
            }
        }
    });
    (address, anchor, task)
}

fn write_anchor(signing_key: &Ed25519SigningKey, label: &str) -> PathBuf {
    let path =
        std::env::temp_dir().join(format!("nanodns-dnssec-{}-{label}.key", std::process::id()));
    fs::write(&path, format!("{}\n", dnskey_record(signing_key))).expect("trust anchor file");
    path
}

fn config(address: SocketAddr, anchor: Option<PathBuf>) -> ResolverConfig {
    ResolverConfig {
        mode: ResolverMode::Forward,
        upstreams: vec![Upstream {
            address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: address.port(),
            tcp: false,
        }],
        timeout_ms: 2_000,
        retries: 0,
        dnssec: true,
        dnssec_trust_anchor: anchor,
        root_hints: Vec::new(),
        root_port: 53,
    }
}

fn query() -> DnsQuery {
    let name = "www.example.test.";
    let mut message = Message::query();
    message.metadata.id = 0x4a21;
    message.add_query(Query::query(
        Name::from_ascii(name).expect("query name"),
        RecordType::A,
    ));

    DnsQuery {
        id: 0x4a21,
        name: name.to_owned(),
        query_type: u16::from(RecordType::A),
        query_class: 1,
        bytes: message.to_vec().expect("query bytes"),
    }
}

fn context() -> QueryContext {
    QueryContext::new(
        ClientIdentity::new(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        Transport::Udp,
    )
}

#[tokio::test]
async fn signed_response_is_validated_and_marked_authentic() {
    let (address, anchor, task) = spawn_stub(StubMode::Signed, "signed").await;
    let resolver =
        DnssecResolver::new(&config(address, Some(anchor.clone()))).expect("validating resolver");
    let response = resolver
        .resolve(query(), &context())
        .await
        .expect("signed response must validate");

    let message = Message::from_vec(&response.bytes).expect("response bytes");
    assert!(message.metadata.authentic_data, "AD flag must be set");
    assert_eq!(message.answers.len(), 2);
    assert_eq!(message.answers[0].record_type(), RecordType::A);

    let _ = fs::remove_file(&anchor);
    task.abort();
}

#[tokio::test]
async fn unsigned_response_without_insecurity_proof_is_rejected() {
    let (address, anchor, task) = spawn_stub(StubMode::Unsigned, "unsigned").await;
    let resolver =
        DnssecResolver::new(&config(address, Some(anchor.clone()))).expect("validating resolver");

    // DNSSEC validation fails closed: an unsigned answer with no NSEC/DS proof of
    // insecurity cannot be distinguished from a stripped signature.
    let error = resolver
        .resolve(query(), &context())
        .await
        .expect_err("unsigned response without proof must fail");
    assert!(
        error.to_string().contains("DNSSEC validation failed"),
        "unexpected error: {error}"
    );

    let _ = fs::remove_file(&anchor);
    task.abort();
}

#[tokio::test]
async fn signature_from_untrusted_key_is_rejected() {
    let (address, stub_anchor, task) = spawn_stub(StubMode::Signed, "untrusted-stub").await;
    let _ = fs::remove_file(&stub_anchor);
    let anchor = write_anchor(&signing_key(), "untrusted");
    let resolver =
        DnssecResolver::new(&config(address, Some(anchor.clone()))).expect("validating resolver");

    let error = resolver
        .resolve(query(), &context())
        .await
        .expect_err("untrusted signature must fail");
    assert!(
        error.to_string().contains("DNSSEC validation failed"),
        "unexpected error: {error}"
    );

    let _ = fs::remove_file(&anchor);
    task.abort();
}

#[test]
fn trust_anchor_file_must_contain_a_dnskey() {
    let path =
        std::env::temp_dir().join(format!("nanodns-dnssec-{}-invalid.key", std::process::id()));
    fs::write(&path, "not a dnskey\n").expect("invalid anchor file");
    assert!(TrustAnchors::from_file(&path).is_err());
    let _ = fs::remove_file(&path);
}

#[test]
fn validating_resolver_requires_forward_mode() {
    let mut settings = config(SocketAddr::from(([127, 0, 0, 1], 53_535)), None);
    assert!(DnssecResolver::new(&settings).is_ok());

    settings.mode = ResolverMode::Recursive;
    assert!(DnssecResolver::new(&settings).is_err());

    settings.mode = ResolverMode::Forward;
    settings.upstreams.clear();
    assert!(DnssecResolver::new(&settings).is_err());
}
