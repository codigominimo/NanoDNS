//! DNSSEC-validating forwarding resolver.
//!
//! Queries are sent to configured upstreams through a minimal [`DnsHandle`]
//! and validated by Hickory's `DnssecDnsHandle`, which follows the full chain
//! of trust (DNSKEY / DS / RRSIG, plus NSEC / NSEC3 for negative answers). A
//! response whose records fail validation is reported as SERVFAIL; a secure
//! response gets the AD flag set before it reaches the client.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{Stream, StreamExt};
use hickory_net::NetError;
use hickory_net::dnssec::DnssecDnsHandle;
use hickory_net::proto::dnssec::{DnssecSummary, TrustAnchors};
use hickory_net::proto::op::{DnsRequest, DnsResponse, Message, ResponseCode};
use hickory_net::runtime::TokioRuntimeProvider;
use hickory_net::xfer::DnsHandle;
use nano_dns_core::config::ResolverConfig;
use nano_dns_core::error::Result as CoreResult;
use nano_dns_core::model::{DnsQuery, QueryContext, Response as CoreResponse};
use nano_dns_core::traits::Resolver;
use tracing::warn;

use crate::error::ResolverError;
use crate::forwarder::{UpstreamTarget, validate_response};
use crate::response::into_core_response;
use crate::transport::{exchange_tcp, exchange_with_truncation};

/// Default EDNS UDP payload size when the client did not advertise one.
const DEFAULT_UDP_PAYLOAD: u16 = 1232;

/// A `DnsHandle` that sends raw DNS messages to the configured upstreams using
/// the same UDP/TCP exchange helpers as the plain forwarder.
#[derive(Clone)]
struct UpstreamHandle {
    upstreams: Arc<Vec<UpstreamTarget>>,
    deadline: Duration,
    retries: u8,
    udp_payload: usize,
}

impl DnsHandle for UpstreamHandle {
    type Response = Pin<Box<dyn Stream<Item = Result<DnsResponse, NetError>> + Send + 'static>>;
    type Runtime = TokioRuntimeProvider;

    fn send(&self, request: DnsRequest) -> Self::Response {
        let (message, _) = request.into_parts();
        let upstreams = Arc::clone(&self.upstreams);
        let deadline = self.deadline;
        let retries = self.retries;
        let udp_payload = self.udp_payload;

        Box::pin(futures_util::stream::once(async move {
            let query_id = message.metadata.id;
            let query_name = message.queries.first().map(|q| q.name().to_string());
            let query_type = message.queries.first().map(|q| q.query_type());
            let query_class = message.queries.first().map(|q| q.query_class());
            let Ok(bytes) = message.to_vec() else {
                return Err(NetError::Msg("cannot serialize DNSSEC query".to_owned()));
            };

            for _attempt in 0..=u32::from(retries) {
                for target in upstreams.iter() {
                    let exchange = if target.tcp_only {
                        exchange_tcp(&bytes, target.address, deadline).await
                    } else {
                        exchange_with_truncation(&bytes, target.address, deadline, udp_payload)
                            .await
                    };

                    let Ok(response) = exchange else {
                        continue;
                    };
                    if response.metadata.id != query_id
                        || response.metadata.message_type
                            != hickory_net::proto::op::MessageType::Response
                        || response.metadata.op_code != hickory_net::proto::op::OpCode::Query
                    {
                        warn!(address = %target.address, "discarding mismatched DNSSEC upstream response");
                        continue;
                    }
                    if let (Some(name), Some(kind), Some(class)) =
                        (query_name.as_deref(), query_type, query_class)
                    {
                        let matches = response.queries.first().is_some_and(|q| {
                            q.name().to_string().eq_ignore_ascii_case(name)
                                && q.query_type() == kind
                                && q.query_class() == class
                        });
                        if !matches {
                            warn!(address = %target.address, "discarding DNSSEC response with mismatched question");
                            continue;
                        }
                    }

                    return DnsResponse::from_message(response).map_err(|error| {
                        NetError::Msg(format!("invalid DNSSEC response: {error}"))
                    });
                }
            }

            Err(NetError::Msg(
                "no upstream returned a valid DNSSEC response".to_owned(),
            ))
        }))
    }
}

/// Resolver that validates every upstream response with DNSSEC before returning it.
#[derive(Clone)]
pub struct DnssecResolver {
    handle: DnssecDnsHandle<UpstreamHandle>,
}

impl DnssecResolver {
    /// Build a validating resolver from validated configuration.
    pub fn new(config: &ResolverConfig) -> CoreResult<Self> {
        if config.mode != nano_dns_core::config::ResolverMode::Forward {
            return Err(ResolverError::Unsupported(
                "DNSSEC validation requires forward resolution mode".to_owned(),
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
                address: std::net::SocketAddr::new(upstream.address, upstream.port),
                tcp_only: upstream.tcp,
            })
            .collect();

        let trust_anchors = match &config.dnssec_trust_anchor {
            Some(path) => TrustAnchors::from_file(path).map_err(|error| {
                ResolverError::Dnssec(format!(
                    "cannot load trust anchor '{}': {error}",
                    path.display()
                ))
            })?,
            None => TrustAnchors::default(),
        };

        let upstream = UpstreamHandle {
            upstreams: Arc::new(upstreams),
            deadline: Duration::from_millis(config.timeout_ms),
            retries: config.retries,
            udp_payload: DEFAULT_UDP_PAYLOAD as usize,
        };

        Ok(Self {
            handle: DnssecDnsHandle::with_trust_anchor(upstream, Arc::new(trust_anchors)),
        })
    }
}

impl Resolver for DnssecResolver {
    type Query = DnsQuery;
    type Future<'a> = Pin<Box<dyn Future<Output = CoreResult<CoreResponse>> + Send + 'a>>;

    fn resolve(&self, query: DnsQuery, _context: &QueryContext) -> Self::Future<'_> {
        let handle = self.handle.clone();
        let requested_id = query.id;

        Box::pin(async move {
            let request = Message::from_vec(&query.bytes).map_err(|error| {
                ResolverError::InvalidResponse {
                    address: std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
                    reason: format!("cannot decode client query for DNSSEC validation: {error}"),
                }
            })?;
            let request = DnsRequest::new(request, Default::default());

            let mut responses = handle.send(request);
            let response = responses.next().await.ok_or_else(|| {
                ResolverError::Dnssec("no validated response was produced".to_owned())
            })?;
            let response = response.map_err(|error| {
                ResolverError::Dnssec(format!("upstream validation failed: {error}"))
            })?;

            let summary = DnssecSummary::from_records(response.answers.iter());
            if summary == DnssecSummary::Bogus {
                return Err(ResolverError::Dnssec("response is bogus".to_owned()).into());
            }

            let (mut message, _buffer) = response.into_parts();
            if message.metadata.id != requested_id {
                message.metadata.id = requested_id;
            }
            if summary == DnssecSummary::Secure {
                message.metadata.authentic_data = true;
            }
            if message.metadata.response_code == ResponseCode::ServFail {
                return Err(ResolverError::Dnssec("upstream returned SERVFAIL".to_owned()).into());
            }

            // Confirm the validated response still answers the client's question.
            let dummy_address = std::net::SocketAddr::from(([127, 0, 0, 1], 0));
            if let Err(error) = validate_response(&message, &query, dummy_address) {
                return Err(error.into());
            }

            into_core_response(message)
        })
    }
}
