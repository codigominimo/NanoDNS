//! Forwarding resolver implementation.
//!
//! Queries are sent unchanged to configured upstreams. UDP is attempted first
//! unless an upstream is marked `tcp: true`; truncated UDP answers are retried
//! over TCP. DNSSEC validation and recursive resolution are future phases.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use nano_dns_core::config::{ResolverConfig, ResolverMode};
use nano_dns_core::error::Result as CoreResult;
use nano_dns_core::model::{DnsQuery, QueryContext, Response as CoreResponse};
use nano_dns_core::traits::Resolver;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;
use tracing::{debug, warn};

use crate::error::ResolverError;

/// Default EDNS UDP payload size when the client did not advertise one.
const DEFAULT_UDP_PAYLOAD: u16 = 1232;

/// One configured upstream resolver.
#[derive(Debug, Clone, PartialEq, Eq)]
struct UpstreamTarget {
    address: SocketAddr,
    tcp_only: bool,
}

/// DNS forwarder backed by one or more upstream resolvers.
#[derive(Debug, Clone)]
pub struct ForwardResolver {
    upstreams: Vec<UpstreamTarget>,
    deadline: Duration,
    retries: u8,
}

impl ForwardResolver {
    /// Build a forwarder from validated resolver configuration.
    pub fn new(config: &ResolverConfig) -> CoreResult<Self> {
        if config.mode != ResolverMode::Forward {
            return Err(ResolverError::Unsupported(
                "recursive mode is implemented in a later phase".to_owned(),
            )
            .into());
        }
        if config.dnssec {
            return Err(ResolverError::Unsupported(
                "DNSSEC validation is implemented in a later phase".to_owned(),
            )
            .into());
        }
        if config.upstreams.is_empty() {
            return Err(ResolverError::Unsupported(
                "resolver.upstreams cannot be empty".to_owned(),
            )
            .into());
        }
        if config.timeout_ms == 0 {
            return Err(ResolverError::Unsupported(
                "resolver.timeout_ms must be greater than zero".to_owned(),
            )
            .into());
        }

        let upstreams = config
            .upstreams
            .iter()
            .map(|upstream| UpstreamTarget {
                address: SocketAddr::new(upstream.address, upstream.port),
                tcp_only: upstream.tcp,
            })
            .collect();

        Ok(Self {
            upstreams,
            deadline: Duration::from_millis(config.timeout_ms),
            retries: config.retries,
        })
    }
}

impl Resolver for ForwardResolver {
    type Query = DnsQuery;
    type Future<'a> = Pin<Box<dyn Future<Output = CoreResult<CoreResponse>> + Send + 'a>>;

    fn resolve(&self, query: DnsQuery, context: &QueryContext) -> Self::Future<'_> {
        let upstreams = self.upstreams.clone();
        let deadline = self.deadline;
        let retries = self.retries;
        let udp_payload =
            usize::from(context.udp_payload_size.unwrap_or(DEFAULT_UDP_PAYLOAD)).max(512);

        Box::pin(async move {
            resolve_with_upstreams(query, upstreams, deadline, retries, udp_payload).await
        })
    }
}

/// Try every upstream for every configured retry.
async fn resolve_with_upstreams(
    query: DnsQuery,
    upstreams: Vec<UpstreamTarget>,
    deadline: Duration,
    retries: u8,
    udp_payload: usize,
) -> CoreResult<CoreResponse> {
    let mut last_error = None;

    for _attempt in 0..=u32::from(retries) {
        for target in &upstreams {
            let exchange = if target.tcp_only {
                exchange_tcp(&query.bytes, target, deadline).await
            } else {
                match exchange_udp(&query.bytes, target, deadline, udp_payload).await {
                    Ok(message) if message.metadata.truncation => {
                        debug!(address = %target.address, "UDP response truncated; retrying over TCP");
                        exchange_tcp(&query.bytes, target, deadline).await
                    }
                    result => result,
                }
            };

            match exchange {
                Ok(message) => match validate_response(&message, &query, target.address) {
                    Ok(()) => return into_core_response(message),
                    Err(error) => {
                        warn!(address = %target.address, %error, "discarding upstream response");
                        last_error = Some(error);
                    }
                },
                Err(error) => {
                    debug!(address = %target.address, %error, "upstream exchange failed");
                    last_error = Some(error);
                }
            }
        }
    }

    if let Some(error) = last_error {
        debug!(%error, "all upstream attempts failed");
    }
    Err(ResolverError::NoUpstream.into())
}

/// Send one UDP query and decode the answer.
async fn exchange_udp(
    query_bytes: &[u8],
    target: &UpstreamTarget,
    deadline: Duration,
    udp_payload: usize,
) -> Result<Message, ResolverError> {
    let bind_address = if target.address.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind_address)
        .await
        .map_err(|source| ResolverError::Io {
            address: target.address,
            source,
        })?;
    socket
        .connect(target.address)
        .await
        .map_err(|source| ResolverError::Io {
            address: target.address,
            source,
        })?;
    socket
        .send(query_bytes)
        .await
        .map_err(|source| ResolverError::Io {
            address: target.address,
            source,
        })?;

    let mut buffer = vec![0u8; udp_payload];
    let len = timeout(deadline, socket.recv(&mut buffer))
        .await
        .map_err(|_| ResolverError::Timeout {
            address: target.address,
            timeout: deadline,
        })?
        .map_err(|source| ResolverError::Io {
            address: target.address,
            source,
        })?;

    Message::from_vec(&buffer[..len]).map_err(|error| ResolverError::InvalidResponse {
        address: target.address,
        reason: error.to_string(),
    })
}

/// Send one length-prefixed TCP query and decode the answer.
async fn exchange_tcp(
    query_bytes: &[u8],
    target: &UpstreamTarget,
    deadline: Duration,
) -> Result<Message, ResolverError> {
    let mut stream =
        TcpStream::connect(target.address)
            .await
            .map_err(|source| ResolverError::Io {
                address: target.address,
                source,
            })?;

    let length = u16::try_from(query_bytes.len()).map_err(|_| ResolverError::InvalidResponse {
        address: target.address,
        reason: "query exceeds DNS TCP length prefix".to_owned(),
    })?;
    stream
        .write_all(&length.to_be_bytes())
        .await
        .map_err(|source| ResolverError::Io {
            address: target.address,
            source,
        })?;
    stream
        .write_all(query_bytes)
        .await
        .map_err(|source| ResolverError::Io {
            address: target.address,
            source,
        })?;

    let mut length_buffer = [0u8; 2];
    timeout(deadline, stream.read_exact(&mut length_buffer))
        .await
        .map_err(|_| ResolverError::Timeout {
            address: target.address,
            timeout: deadline,
        })?
        .map_err(|source| ResolverError::Io {
            address: target.address,
            source,
        })?;

    let mut buffer = vec![0u8; usize::from(u16::from_be_bytes(length_buffer))];
    timeout(deadline, stream.read_exact(&mut buffer))
        .await
        .map_err(|_| ResolverError::Timeout {
            address: target.address,
            timeout: deadline,
        })?
        .map_err(|source| ResolverError::Io {
            address: target.address,
            source,
        })?;

    Message::from_vec(&buffer).map_err(|error| ResolverError::InvalidResponse {
        address: target.address,
        reason: error.to_string(),
    })
}

/// Reject responses that do not answer the original question.
fn validate_response(
    message: &Message,
    query: &DnsQuery,
    address: SocketAddr,
) -> Result<(), ResolverError> {
    let invalid = |reason: &str| ResolverError::InvalidResponse {
        address,
        reason: reason.to_owned(),
    };

    if message.metadata.id != query.id {
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
    if question.name().to_string().to_lowercase() != query.name
        || u16::from(question.query_type()) != query.query_type
        || u16::from(question.query_class()) != query.query_class
    {
        return Err(invalid("question does not match the request"));
    }

    Ok(())
}

/// Convert a validated Hickory message into the core response representation.
fn into_core_response(message: Message) -> CoreResult<CoreResponse> {
    let ttl_secs = message
        .answers
        .iter()
        .map(|record| record.ttl)
        .min()
        .unwrap_or_default();
    let negative = message.metadata.response_code == ResponseCode::NXDomain
        || (message.metadata.response_code == ResponseCode::NoError && message.answers.is_empty());
    let bytes = message
        .to_vec()
        .map_err(|error| ResolverError::Encode(error.to_string()))?;

    Ok(CoreResponse {
        bytes,
        ttl_secs,
        negative,
    })
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use hickory_proto::op::{Query, ResponseCode};
    use hickory_proto::rr::{Name, RData, Record, RecordType, rdata::A};
    use nano_dns_core::config::Upstream;
    use nano_dns_core::model::ClientIdentity;

    use super::*;

    fn forward_config() -> ResolverConfig {
        ResolverConfig {
            mode: ResolverMode::Forward,
            upstreams: vec![Upstream::default()],
            timeout_ms: 2_000,
            retries: 2,
            dnssec: false,
            root_hints: Vec::new(),
        }
    }

    fn query() -> DnsQuery {
        DnsQuery {
            id: 7,
            name: "example.com.".to_owned(),
            query_type: u16::from(RecordType::A),
            query_class: 1,
            bytes: Vec::new(),
        }
    }

    fn response(query: &DnsQuery) -> Message {
        let mut message = Message::response(query.id, OpCode::Query);
        message.add_query(Query::query(
            Name::from_ascii(&query.name).expect("valid name"),
            RecordType::A,
        ));
        message.add_answer(Record::from_rdata(
            Name::from_ascii(&query.name).expect("valid name"),
            60,
            RData::A(A::new(127, 0, 0, 1)),
        ));
        message
    }

    #[test]
    fn valid_forward_config_is_accepted() {
        let config = forward_config();
        ForwardResolver::new(&config).expect("forwarder must build");
    }

    #[test]
    fn recursive_and_dnssec_modes_are_rejected() {
        let mut config = forward_config();
        config.mode = ResolverMode::Recursive;
        assert!(ForwardResolver::new(&config).is_err());

        let mut config = forward_config();
        config.dnssec = true;
        assert!(ForwardResolver::new(&config).is_err());
    }

    #[test]
    fn responses_are_validated_against_the_question() {
        let query = query();
        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53);
        let message = response(&query);
        validate_response(&message, &query, address).expect("response must match");

        let mut wrong_id = response(&query);
        wrong_id.metadata.id += 1;
        assert!(validate_response(&wrong_id, &query, address).is_err());
    }

    #[test]
    fn core_response_keeps_ttl_and_detects_negative_answers() {
        let query = query();
        let core = into_core_response(response(&query)).expect("response must convert");
        assert_eq!(core.ttl_secs, 60);
        assert!(!core.negative);

        let mut nxdomain = Message::response(query.id, OpCode::Query);
        nxdomain.metadata.response_code = ResponseCode::NXDomain;
        let core = into_core_response(nxdomain).expect("response must convert");
        assert!(core.negative);
    }

    #[test]
    fn context_without_edns_uses_default_payload() {
        let context = QueryContext::new(
            ClientIdentity::new(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            nano_dns_core::model::Transport::Udp,
        );
        assert_eq!(
            context.udp_payload_size.unwrap_or(DEFAULT_UDP_PAYLOAD),
            1232
        );
    }
}
