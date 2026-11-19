//! Forwarding resolver implementation.
//!
//! Queries are sent unchanged to configured upstreams. UDP is attempted first
//! unless an upstream is marked `tcp: true`; truncated UDP answers are retried
//! over TCP. DNSSEC validation and recursive resolution live in separate
//! modules.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode};
use nano_dns_core::config::{ResolverConfig, ResolverMode};
use nano_dns_core::error::Result as CoreResult;
use nano_dns_core::model::{DnsQuery, QueryContext, Response as CoreResponse};
use nano_dns_core::traits::Resolver;
use tracing::{debug, warn};

use crate::error::ResolverError;
use crate::response::into_core_response;
use crate::transport::{exchange_tcp, exchange_with_truncation};

/// Default EDNS UDP payload size when the client did not advertise one.
const DEFAULT_UDP_PAYLOAD: u16 = 1232;

/// One configured upstream resolver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UpstreamTarget {
    pub(crate) address: SocketAddr,
    pub(crate) tcp_only: bool,
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
                "forward resolver requires forward mode".to_owned(),
            )
            .into());
        }
        if config.dnssec {
            return Err(ResolverError::Unsupported(
                "DNSSEC validation is provided by DnssecResolver, not ForwardResolver".to_owned(),
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
                exchange_tcp(&query.bytes, target.address, deadline).await
            } else {
                exchange_with_truncation(&query.bytes, target.address, deadline, udp_payload).await
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

/// Reject responses that do not answer the original question.
pub(crate) fn validate_response(
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
            dnssec_trust_anchor: None,
            root_hints: Vec::new(),
            root_port: 53,
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
