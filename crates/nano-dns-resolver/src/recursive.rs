//! Iterative recursive resolver implementation.
//!
//! Resolution starts at the configured root hints and follows NS referrals
//! until an authoritative answer is found. CNAME chains are followed, loops
//! are bounded, and the final response is rewritten for the original client
//! transaction. DNSSEC validation remains a later phase.

use std::collections::HashSet;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use nano_dns_core::config::ResolverConfig;
use nano_dns_core::error::Result as CoreResult;
use nano_dns_core::model::{DnsQuery, QueryContext, Response as CoreResponse};
use nano_dns_core::traits::Resolver;
use tracing::debug;

use crate::error::ResolverError;
use crate::response::into_core_response;
use crate::transport::exchange_with_truncation;

/// Default EDNS UDP payload size when the client did not advertise one.
const DEFAULT_UDP_PAYLOAD: u16 = 1232;
/// Maximum number of CNAME/referral hops.
const MAX_DEPTH: u8 = 16;
/// Maximum number of iterative exchanges per name.
const MAX_ITERATIONS: usize = 32;

static NEXT_ID: AtomicU16 = AtomicU16::new(1);

/// Iterative resolver backed by configured root hints.
#[derive(Debug, Clone)]
pub struct RecursiveResolver {
    roots: Vec<SocketAddr>,
    deadline: Duration,
    retries: u8,
    udp_payload: u16,
}

/// Immutable state shared by one client resolution.
struct Iteration<'a> {
    roots: &'a [SocketAddr],
    port: u16,
    deadline: Duration,
    retries: u8,
    udp_payload: usize,
    original: Query,
    original_id: u16,
}

impl RecursiveResolver {
    /// Build a recursive resolver from validated resolver configuration.
    pub fn new(config: &ResolverConfig) -> CoreResult<Self> {
        if config.root_hints.is_empty() {
            return Err(ResolverError::Unsupported(
                "resolver.root_hints cannot be empty in recursive mode".to_owned(),
            )
            .into());
        }
        if config.root_port == 0 {
            return Err(ResolverError::Unsupported(
                "resolver.root_port must be greater than zero".to_owned(),
            )
            .into());
        }
        if config.timeout_ms == 0 {
            return Err(ResolverError::Unsupported(
                "resolver.timeout_ms must be greater than zero".to_owned(),
            )
            .into());
        }
        if config.dnssec {
            return Err(ResolverError::Unsupported(
                "DNSSEC validation is implemented in a later phase".to_owned(),
            )
            .into());
        }

        let roots = config
            .root_hints
            .iter()
            .map(|address| SocketAddr::new(*address, config.root_port))
            .collect();

        Ok(Self {
            roots,
            deadline: Duration::from_millis(config.timeout_ms),
            retries: config.retries,
            udp_payload: DEFAULT_UDP_PAYLOAD,
        })
    }
}

impl Resolver for RecursiveResolver {
    type Query = DnsQuery;
    type Future<'a> = Pin<Box<dyn Future<Output = CoreResult<CoreResponse>> + Send + 'a>>;

    fn resolve(&self, query: DnsQuery, context: &QueryContext) -> Self::Future<'_> {
        let roots = self.roots.clone();
        let deadline = self.deadline;
        let retries = self.retries;
        let udp_payload = context
            .udp_payload_size
            .unwrap_or(self.udp_payload)
            .max(512) as usize;

        Box::pin(async move {
            let request = Message::from_vec(&query.bytes).map_err(|error| {
                ResolverError::InvalidResponse {
                    address: roots[0],
                    reason: format!("cannot decode client query: {error}"),
                }
            })?;
            if request.queries.len() != 1 {
                return Err(ResolverError::Unsupported(
                    "recursive resolver expects exactly one question".to_owned(),
                )
                .into());
            }

            let original = request.queries[0].clone();
            let state = Iteration {
                roots: &roots,
                port: roots[0].port(),
                deadline,
                retries,
                udp_payload,
                original: original.clone(),
                original_id: query.id,
            };

            let answer = resolve_name(
                &state,
                original.name().clone(),
                original.query_type(),
                original.query_class(),
                Vec::new(),
                0,
            )
            .await?;
            into_core_response(answer)
        })
    }
}

/// Resolve one name iteratively, following referrals and CNAME chains.
fn resolve_name<'a>(
    state: &'a Iteration<'a>,
    name: Name,
    query_type: RecordType,
    query_class: DNSClass,
    accumulated: Vec<Record>,
    depth: u8,
) -> Pin<Box<dyn Future<Output = Result<Message, ResolverError>> + Send + 'a>> {
    Box::pin(async move {
        if depth > MAX_DEPTH {
            return Err(ResolverError::Unsupported(
                "recursive resolution exceeded the CNAME/referral limit".to_owned(),
            ));
        }

        let mut servers = state.roots.to_vec();
        let current = name;
        let mut accumulated = accumulated;

        for _ in 0..MAX_ITERATIONS {
            let response =
                query_servers(state, &servers, current.clone(), query_type, query_class).await?;
            let code = response.metadata.response_code;

            let cnames: Vec<Record> = response
                .answers
                .iter()
                .filter(|record| {
                    record.record_type() == RecordType::CNAME && same_name(&record.name, &current)
                })
                .cloned()
                .collect();
            let has_final_answer = response.answers.iter().any(|record| {
                record.record_type() == query_type
                    || (query_type == RecordType::ANY && record.record_type() != RecordType::CNAME)
            });

            if has_final_answer {
                return Ok(finalize(state, response, accumulated));
            }

            if code == ResponseCode::NXDomain {
                return Ok(finalize(state, response, accumulated));
            }

            if let Some(target) = cname_target(&cnames) {
                if depth == MAX_DEPTH {
                    return Err(ResolverError::Unsupported(
                        "recursive resolution exceeded the CNAME limit".to_owned(),
                    ));
                }
                if accumulated
                    .iter()
                    .any(|record| same_name(&record.name, &target))
                {
                    return Err(ResolverError::Unsupported("CNAME loop detected".to_owned()));
                }
                accumulated.extend(cnames);
                return resolve_name(
                    state,
                    target,
                    query_type,
                    query_class,
                    accumulated,
                    depth + 1,
                )
                .await;
            }

            if code == ResponseCode::NoError
                && response.metadata.authoritative
                && response
                    .authorities
                    .iter()
                    .any(|record| record.record_type() == RecordType::SOA)
            {
                return Ok(finalize(state, response, accumulated));
            }

            let delegated = ns_names(&response.authorities);
            if !delegated.is_empty() {
                servers =
                    delegated_addresses(state, &delegated, &response.additionals, depth).await?;
                continue;
            }

            return Ok(finalize(state, response, accumulated));
        }

        Err(ResolverError::Unsupported(
            "recursive resolution exceeded the iteration limit".to_owned(),
        ))
    })
}

/// Ask a set of servers until one returns a usable response.
async fn query_servers(
    state: &Iteration<'_>,
    servers: &[SocketAddr],
    name: Name,
    query_type: RecordType,
    query_class: DNSClass,
) -> Result<Message, ResolverError> {
    if servers.is_empty() {
        return Err(ResolverError::Unsupported(
            "no nameservers available for delegation".to_owned(),
        ));
    }

    let mut last_error = None;
    for _attempt in 0..=u32::from(state.retries) {
        for &server in servers {
            let mut message = Message::query();
            message.metadata.id = next_id();
            message.metadata.recursion_desired = false;
            let mut question = Query::query(name.clone(), query_type);
            question.set_query_class(query_class);
            message.add_query(question);

            let bytes = message
                .to_vec()
                .map_err(|error| ResolverError::Encode(error.to_string()))?;
            let answer =
                exchange_with_truncation(&bytes, server, state.deadline, state.udp_payload).await;

            let answer = match answer {
                Ok(answer) => answer,
                Err(error) => {
                    debug!(%server, %error, "iterative exchange failed");
                    last_error = Some(error);
                    continue;
                }
            };

            if let Err(error) = validate(
                &answer,
                message.metadata.id,
                &name,
                query_type,
                query_class,
                server,
            ) {
                debug!(%server, %error, "discarding iterative response");
                last_error = Some(error);
                continue;
            }

            if matches!(
                answer.metadata.response_code,
                ResponseCode::ServFail
                    | ResponseCode::Refused
                    | ResponseCode::FormErr
                    | ResponseCode::NotImp
            ) {
                last_error = Some(ResolverError::InvalidResponse {
                    address: server,
                    reason: format!("server returned {:?}", answer.metadata.response_code),
                });
                continue;
            }

            return Ok(answer);
        }
    }

    Err(last_error.unwrap_or(ResolverError::NoUpstream))
}

/// Validate an iterative response against the query that produced it.
fn validate(
    message: &Message,
    id: u16,
    name: &Name,
    query_type: RecordType,
    query_class: DNSClass,
    address: SocketAddr,
) -> Result<(), ResolverError> {
    let invalid = |reason: &str| ResolverError::InvalidResponse {
        address,
        reason: reason.to_owned(),
    };

    if message.metadata.id != id {
        return Err(invalid("transaction id mismatch"));
    }
    if message.metadata.message_type != MessageType::Response {
        return Err(invalid("message is not a response"));
    }
    if message.metadata.op_code != OpCode::Query {
        return Err(invalid("unexpected opcode"));
    }
    if message.queries.len() != 1 {
        return Err(invalid("expected exactly one question"));
    }

    let question = &message.queries[0];
    if !same_name(question.name(), name)
        || question.query_type() != query_type
        || question.query_class() != query_class
    {
        return Err(invalid("question does not match the iterative query"));
    }

    Ok(())
}

/// Extract the first CNAME target pointing at the name being resolved.
fn cname_target(records: &[Record]) -> Option<Name> {
    records.iter().find_map(|record| match &record.data {
        RData::CNAME(target) => Some(target.0.clone()),
        _ => None,
    })
}

/// Extract NS target names from an authority section.
fn ns_names(records: &[Record]) -> Vec<Name> {
    let mut names = Vec::new();
    for record in records {
        if let RData::NS(target) = &record.data
            && !names.iter().any(|name| same_name(name, &target.0))
        {
            names.push(target.0.clone());
        }
    }
    names
}

/// Collect addresses for delegated nameservers, preferring glue records.
async fn delegated_addresses(
    state: &Iteration<'_>,
    names: &[Name],
    additionals: &[Record],
    depth: u8,
) -> Result<Vec<SocketAddr>, ResolverError> {
    let mut addresses = Vec::new();
    for name in names {
        for record in additionals {
            if !same_name(&record.name, name) {
                continue;
            }
            match &record.data {
                RData::A(address) => {
                    addresses.push(SocketAddr::new(IpAddr::V4((*address).into()), state.port));
                }
                RData::AAAA(address) => {
                    addresses.push(SocketAddr::new(IpAddr::V6((*address).into()), state.port));
                }
                _ => {}
            }
        }
    }
    addresses.sort();
    addresses.dedup();
    if !addresses.is_empty() {
        return Ok(addresses);
    }

    if depth < MAX_DEPTH {
        for name in names {
            for query_type in [RecordType::A, RecordType::AAAA] {
                if let Ok(message) = resolve_name(
                    state,
                    name.clone(),
                    query_type,
                    DNSClass::IN,
                    Vec::new(),
                    depth + 1,
                )
                .await
                {
                    for record in &message.answers {
                        match &record.data {
                            RData::A(address) => addresses
                                .push(SocketAddr::new(IpAddr::V4((*address).into()), state.port)),
                            RData::AAAA(address) => addresses
                                .push(SocketAddr::new(IpAddr::V6((*address).into()), state.port)),
                            _ => {}
                        }
                    }
                }
            }
        }
    }

    addresses.sort();
    addresses.dedup();
    if addresses.is_empty() {
        Err(ResolverError::Unsupported(
            "delegated nameservers have no usable addresses".to_owned(),
        ))
    } else {
        Ok(addresses)
    }
}

/// Rewrite the authoritative answer for the original client transaction.
fn finalize(state: &Iteration<'_>, mut response: Message, accumulated: Vec<Record>) -> Message {
    response.metadata.id = state.original_id;
    response.metadata.message_type = MessageType::Response;
    response.metadata.op_code = OpCode::Query;
    response.metadata.recursion_available = true;
    response.queries = vec![state.original.clone()];

    if !accumulated.is_empty() {
        let mut answers = accumulated;
        answers.extend(response.answers.iter().cloned());
        response.answers = deduplicate(answers);
    }
    response
}

/// Remove repeated records produced by CNAME chains and authoritative answers.
fn deduplicate(records: Vec<Record>) -> Vec<Record> {
    let mut seen = HashSet::new();
    records
        .into_iter()
        .filter(|record| {
            let key = format!(
                "{}|{}|{}|{}",
                record.name.to_string().to_lowercase(),
                u16::from(record.record_type()),
                record.ttl,
                record.data
            );
            seen.insert(key)
        })
        .collect()
}

/// Compare names without relying on case or trailing-dot representation.
fn same_name(left: &Name, right: &Name) -> bool {
    left.to_string()
        .trim_end_matches('.')
        .eq_ignore_ascii_case(right.to_string().trim_end_matches('.'))
}

fn next_id() -> u16 {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    if id == 0 { 1 } else { id }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use hickory_proto::op::{Metadata, ResponseCode};
    use hickory_proto::rr::{
        RData, Record, RecordType,
        rdata::{A, CNAME, NS, SOA},
    };
    use nano_dns_core::config::{ResolverMode, Upstream};
    use nano_dns_core::model::ClientIdentity;
    use tokio::net::UdpSocket;

    use super::*;

    fn free_port() -> u16 {
        std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .expect("free port")
            .local_addr()
            .expect("local address")
            .port()
    }

    fn config(port: u16) -> ResolverConfig {
        ResolverConfig {
            mode: ResolverMode::Recursive,
            upstreams: vec![Upstream::default()],
            timeout_ms: 1_000,
            retries: 0,
            dnssec: false,
            root_hints: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
            root_port: port,
        }
    }

    fn query_bytes(id: u16, name: &str, query_type: RecordType) -> Vec<u8> {
        let mut message = Message::query();
        message.metadata.id = id;
        let mut query = Query::query(Name::from_ascii(name).expect("valid name"), query_type);
        query.set_query_class(DNSClass::IN);
        message.add_query(query);
        message.to_vec().expect("query must encode")
    }

    fn answer(request: &Message, rcode: ResponseCode) -> Message {
        let mut response = Message::response(request.metadata.id, OpCode::Query);
        response.metadata = Metadata::response_from_request(&request.metadata);
        response.metadata.response_code = rcode;
        response.add_queries(request.queries.iter().cloned());
        response
    }

    fn delegation(response: &mut Message, zone: &str, server: &str, glue: Ipv4Addr) {
        response.metadata.authoritative = false;
        response.add_authority(Record::from_rdata(
            Name::from_ascii(zone).expect("valid zone"),
            300,
            RData::NS(NS(Name::from_ascii(server).expect("valid server"))),
        ));
        response.add_additional(Record::from_rdata(
            Name::from_ascii(server).expect("valid server"),
            300,
            RData::A(A::from(glue)),
        ));
    }

    async fn spawn_stub(
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
                let response = handler(request);
                if let Ok(bytes) = response.to_vec() {
                    let _ = socket.send_to(&bytes, src).await;
                }
            }
        });
    }

    fn core_query(_port: u16, name: &str) -> DnsQuery {
        DnsQuery {
            id: 42,
            name: name.to_owned(),
            query_type: u16::from(RecordType::A),
            query_class: u16::from(DNSClass::IN),
            bytes: query_bytes(42, name, RecordType::A),
        }
    }

    fn context() -> QueryContext {
        QueryContext::new(
            ClientIdentity::new(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            nano_dns_core::model::Transport::Udp,
        )
    }

    #[tokio::test]
    async fn follows_referrals_to_an_authoritative_answer() {
        let port = free_port();
        spawn_stub(Ipv4Addr::LOCALHOST, port, |request| {
            let mut response = answer(&request, ResponseCode::NoError);
            delegation(
                &mut response,
                "com.",
                "ns.com.",
                Ipv4Addr::new(127, 0, 0, 2),
            );
            response
        })
        .await;
        spawn_stub(Ipv4Addr::new(127, 0, 0, 2), port, |request| {
            let mut response = answer(&request, ResponseCode::NoError);
            delegation(
                &mut response,
                "example.com.",
                "ns.example.com.",
                Ipv4Addr::new(127, 0, 0, 3),
            );
            response
        })
        .await;
        spawn_stub(Ipv4Addr::new(127, 0, 0, 3), port, |request| {
            let mut response = answer(&request, ResponseCode::NoError);
            response.metadata.authoritative = true;
            response.add_answer(Record::from_rdata(
                request.queries[0].name().clone(),
                120,
                RData::A(A::new(192, 0, 2, 10)),
            ));
            response
        })
        .await;

        let resolver = RecursiveResolver::new(&config(port)).expect("resolver must build");
        let core = resolver
            .resolve(core_query(port, "www.example.com."), &context())
            .await
            .expect("resolution must succeed");
        let response = Message::from_vec(&core.bytes).expect("response must decode");

        assert_eq!(response.metadata.id, 42);
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert_eq!(response.answers.len(), 1);
        assert!(
            matches!(&response.answers[0].data, RData::A(address) if Ipv4Addr::from(*address) == Ipv4Addr::new(192, 0, 2, 10))
        );
        assert_eq!(core.ttl_secs, 120);
    }

    #[tokio::test]
    async fn propagates_authoritative_nxdomain() {
        let port = free_port();
        spawn_stub(Ipv4Addr::LOCALHOST, port, |request| {
            let mut response = answer(&request, ResponseCode::NoError);
            delegation(
                &mut response,
                "com.",
                "ns.com.",
                Ipv4Addr::new(127, 0, 0, 2),
            );
            response
        })
        .await;
        spawn_stub(Ipv4Addr::new(127, 0, 0, 2), port, |request| {
            let mut response = answer(&request, ResponseCode::NXDomain);
            response.metadata.authoritative = true;
            response.add_authority(Record::from_rdata(
                Name::from_ascii("com.").expect("valid zone"),
                60,
                RData::SOA(SOA::new(
                    Name::from_ascii("ns.com.").expect("valid mname"),
                    Name::from_ascii("hostmaster.com.").expect("valid rname"),
                    1,
                    7200,
                    3600,
                    1209600,
                    60,
                )),
            ));
            response
        })
        .await;

        let resolver = RecursiveResolver::new(&config(port)).expect("resolver must build");
        let core = resolver
            .resolve(core_query(port, "missing.example."), &context())
            .await
            .expect("resolution must succeed");
        let response = Message::from_vec(&core.bytes).expect("response must decode");

        assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
        assert!(core.negative);
    }

    #[tokio::test]
    async fn follows_cname_chains() {
        let port = free_port();
        spawn_stub(Ipv4Addr::LOCALHOST, port, |request| {
            let mut response = answer(&request, ResponseCode::NoError);
            response.metadata.authoritative = true;
            if request.queries[0]
                .name()
                .to_string()
                .to_lowercase()
                .starts_with("alias")
            {
                response.add_answer(Record::from_rdata(
                    request.queries[0].name().clone(),
                    120,
                    RData::CNAME(CNAME(
                        Name::from_ascii("target.example.").expect("valid target"),
                    )),
                ));
            } else {
                response.add_answer(Record::from_rdata(
                    request.queries[0].name().clone(),
                    90,
                    RData::A(A::new(192, 0, 2, 20)),
                ));
            }
            response
        })
        .await;

        let resolver = RecursiveResolver::new(&config(port)).expect("resolver must build");
        let core = resolver
            .resolve(core_query(port, "alias.example."), &context())
            .await
            .expect("resolution must succeed");
        let response = Message::from_vec(&core.bytes).expect("response must decode");

        assert_eq!(response.answers.len(), 2);
        assert_eq!(response.answers[0].record_type(), RecordType::CNAME);
        assert_eq!(response.answers[1].record_type(), RecordType::A);
    }
}
