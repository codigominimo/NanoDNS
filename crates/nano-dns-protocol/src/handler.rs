//! Request parsing, validation and response dispatch.
//!
//! Phase 2 accepted and validated DNS messages and answered `NOTIMP`.
//! Phase 3 forwards valid queries to the configured resolver pipeline.

use std::net::IpAddr;
use std::sync::Arc;

use hickory_proto::op::{
    Header, HeaderCounts, Message, MessageType, Metadata, OpCode, ResponseCode,
};
use hickory_proto::rr::Record;
use hickory_server::net::runtime::Time;
use hickory_server::net::xfer::Protocol;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::MessageResponseBuilder;
use nano_dns_core::config::{ClientConfig, Listeners};
use nano_dns_core::model::{
    ClientIdentity, DnsQuery, QueryContext, Response as CoreResponse, Transport,
};
use nano_dns_core::traits::Resolver;
use tokio::sync::Semaphore;
use tracing::{debug, trace, warn};

/// Limits applied to every incoming request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestLimits {
    /// Maximum accepted message size in bytes.
    pub max_packet_bytes: usize,
    /// Maximum number of concurrent requests handled by the listener set.
    pub max_concurrent_queries: usize,
}

impl RequestLimits {
    /// Build limits from global listener configuration.
    pub fn from_config(config: &Listeners) -> Self {
        Self {
            max_packet_bytes: config.max_packet_bytes,
            max_concurrent_queries: config.max_concurrent_queries,
        }
    }
}

/// Handler installed in the Hickory DNS server.
pub struct NanoRequestHandler<R>
where
    R: Resolver<Query = DnsQuery>,
{
    resolver: Arc<R>,
    limits: Arc<RequestLimits>,
    clients: Arc<Vec<ClientConfig>>,
    permits: Arc<Semaphore>,
}

impl<R> Clone for NanoRequestHandler<R>
where
    R: Resolver<Query = DnsQuery>,
{
    fn clone(&self) -> Self {
        Self {
            resolver: Arc::clone(&self.resolver),
            limits: Arc::clone(&self.limits),
            clients: Arc::clone(&self.clients),
            permits: Arc::clone(&self.permits),
        }
    }
}

impl<R> NanoRequestHandler<R>
where
    R: Resolver<Query = DnsQuery>,
{
    /// Create a handler with the given limits, client rules and resolver.
    pub fn new(limits: RequestLimits, clients: Vec<ClientConfig>, resolver: R) -> Self {
        let permits = Arc::new(Semaphore::new(limits.max_concurrent_queries.max(1)));
        Self {
            resolver: Arc::new(resolver),
            limits: Arc::new(limits),
            clients: Arc::new(clients),
            permits,
        }
    }

    /// Decode and validate a request message.
    fn decode(&self, request: &Request) -> Result<Message, ResponseCode> {
        if request.as_slice().len() > self.limits.max_packet_bytes {
            debug!(
                len = request.as_slice().len(),
                "DNS request exceeds size limit"
            );
            return Err(ResponseCode::FormErr);
        }

        let message = Message::from_vec(request.as_slice()).map_err(|error| {
            debug!(%error, "cannot decode DNS request");
            ResponseCode::FormErr
        })?;

        if message.metadata.message_type != MessageType::Query
            || message.metadata.op_code != OpCode::Query
        {
            debug!(
                message_type = ?message.metadata.message_type,
                op_code = ?message.metadata.op_code,
                "unsupported DNS operation"
            );
            return Err(ResponseCode::NotImp);
        }

        if message.metadata.response_code != ResponseCode::NoError {
            debug!(code = ?message.metadata.response_code, "query carries a response code");
            return Err(ResponseCode::FormErr);
        }

        if message.queries.len() != 1 {
            debug!(
                count = message.queries.len(),
                "expected exactly one DNS question"
            );
            return Err(ResponseCode::FormErr);
        }

        Ok(message)
    }

    /// Resolve a configured client identity from the socket peer address.
    fn identify_client(&self, address: IpAddr) -> ClientIdentity {
        let id = self
            .clients
            .iter()
            .find(|client| {
                client
                    .networks
                    .iter()
                    .any(|network| network.contains(&address))
            })
            .map(|client| client.id.clone());
        ClientIdentity { id, address }
    }

    /// Build the query context for a validated message.
    fn context(&self, request: &Request, message: &Message) -> QueryContext {
        let transport = match request.protocol() {
            Protocol::Udp => Transport::Udp,
            Protocol::Tcp => Transport::Tcp,
            _ => Transport::Tcp,
        };

        let mut context = QueryContext::new(self.identify_client(request.src().ip()), transport);
        if let Some(edns) = message.edns.as_ref() {
            context.edns = true;
            context.udp_payload_size = Some(edns.max_payload());
            context.dnssec_ok = edns.flags().dnssec_ok;
        }
        context
    }

    /// Build the protocol-neutral query passed to the resolver pipeline.
    fn query(request: &Request, message: &Message) -> DnsQuery {
        let question = &message.queries[0];
        DnsQuery {
            id: message.metadata.id,
            name: question.name().to_string().to_lowercase(),
            query_type: u16::from(question.query_type()),
            query_class: u16::from(question.query_class()),
            bytes: request.as_slice().to_vec(),
        }
    }

    /// Build a minimal `ResponseInfo` when the response could not be sent.
    fn failed_response(request: &Request, code: ResponseCode) -> ResponseInfo {
        let mut metadata = Metadata::response_from_request(&request.metadata);
        metadata.response_code = code;
        ResponseInfo::from(Header {
            metadata,
            counts: HeaderCounts::default(),
        })
    }

    /// Send an error response derived from the original request.
    async fn send_error<S: ResponseHandler>(
        &self,
        request: &Request,
        mut handle: S,
        code: ResponseCode,
    ) -> ResponseInfo {
        let mut builder = MessageResponseBuilder::from_message_request(request);
        if let Some(edns) = request.edns.as_ref() {
            builder.edns(edns);
        }
        let response = builder.error_msg(&request.metadata, code);
        handle
            .send_response(response)
            .await
            .unwrap_or_else(|error| {
                warn!(%error, "cannot send DNS error response");
                Self::failed_response(request, ResponseCode::ServFail)
            })
    }

    /// Send a resolved response while preserving the client transaction id.
    async fn send_resolved<S: ResponseHandler>(
        &self,
        request: &Request,
        core_response: CoreResponse,
        mut handle: S,
    ) -> ResponseInfo {
        let message = match Message::from_vec(&core_response.bytes) {
            Ok(message) => message,
            Err(error) => {
                warn!(%error, "resolver returned an invalid DNS message");
                return self
                    .send_error(request, handle, ResponseCode::ServFail)
                    .await;
            }
        };

        let edns = message.edns.as_ref().or(request.edns.as_ref());
        let mut metadata = message.metadata;
        metadata.id = request.metadata.id;

        let response = MessageResponseBuilder::new(&request.queries, edns).build(
            metadata,
            &message.answers,
            &message.authorities,
            std::iter::empty::<&Record>(),
            &message.additionals,
        );

        handle
            .send_response(response)
            .await
            .unwrap_or_else(|error| {
                warn!(%error, "cannot send DNS response");
                Self::failed_response(request, ResponseCode::ServFail)
            })
    }
}

#[async_trait::async_trait]
impl<R> RequestHandler for NanoRequestHandler<R>
where
    R: Resolver<Query = DnsQuery> + 'static,
{
    async fn handle_request<S: ResponseHandler, T: Time>(
        &self,
        request: &Request,
        response_handle: S,
    ) -> ResponseInfo {
        let message = match self.decode(request) {
            Ok(message) => message,
            Err(code) => return self.send_error(request, response_handle, code).await,
        };

        let permit = match Arc::clone(&self.permits).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                debug!("concurrency limit reached; refusing query");
                return self
                    .send_error(request, response_handle, ResponseCode::Refused)
                    .await;
            }
        };

        let context = self.context(request, &message);
        trace!(
            name = %message.queries[0].name(),
            qtype = %message.queries[0].query_type(),
            client_id = ?context.client.id,
            transport = ?context.transport,
            "DNS query accepted"
        );

        let query = Self::query(request, &message);
        let result = self.resolver.resolve(query, &context).await;
        let outcome = match result {
            Ok(response) => self.send_resolved(request, response, response_handle).await,
            Err(error) => {
                warn!(%error, "resolution failed");
                self.send_error(request, response_handle, ResponseCode::ServFail)
                    .await
            }
        };

        drop(permit);
        outcome
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::pin::Pin;

    use hickory_proto::op::{Edns, Query};
    use hickory_proto::rr::{Name, RecordType};
    use ipnet::{IpNet, Ipv4Net};
    use nano_dns_core::config::Listeners;
    use nano_dns_core::error::Result as CoreResult;

    #[derive(Clone)]
    struct StubResolver;

    impl Resolver for StubResolver {
        type Query = DnsQuery;
        type Future<'a> = Pin<Box<dyn Future<Output = CoreResult<CoreResponse>> + Send + 'a>>;

        fn resolve(&self, _query: DnsQuery, _context: &QueryContext) -> Self::Future<'_> {
            Box::pin(async {
                Ok(CoreResponse {
                    bytes: Vec::new(),
                    ttl_secs: 0,
                    negative: false,
                })
            })
        }
    }

    fn handler(
        limits: RequestLimits,
        clients: Vec<ClientConfig>,
    ) -> NanoRequestHandler<StubResolver> {
        NanoRequestHandler::new(limits, clients, StubResolver)
    }

    fn limits() -> RequestLimits {
        RequestLimits::from_config(&Listeners::default())
    }

    fn request(bytes: Vec<u8>) -> Request {
        Request::from_bytes(
            bytes,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53_333),
            Protocol::Udp,
        )
        .expect("request must decode")
    }

    fn query_message() -> Vec<u8> {
        let mut message = Message::query();
        message.add_query(Query::query(
            Name::from_ascii("example.com.").expect("valid name"),
            RecordType::A,
        ));
        message.to_vec().expect("message must encode")
    }

    #[test]
    fn valid_query_is_decoded() {
        let handler = handler(limits(), Vec::new());
        let request = request(query_message());
        let message = handler.decode(&request).expect("valid query");
        assert_eq!(message.queries.len(), 1);
    }

    #[test]
    fn query_without_questions_is_rejected() {
        let handler = handler(limits(), Vec::new());
        let request = request(Message::query().to_vec().expect("message must encode"));
        assert_eq!(handler.decode(&request), Err(ResponseCode::FormErr));
    }

    #[test]
    fn oversized_packet_is_rejected() {
        let handler = handler(
            RequestLimits {
                max_packet_bytes: 12,
                max_concurrent_queries: 4,
            },
            Vec::new(),
        );
        let request = request(query_message());
        assert_eq!(handler.decode(&request), Err(ResponseCode::FormErr));
    }

    #[test]
    fn multiple_questions_are_rejected() {
        let mut message = Message::query();
        message.add_query(Query::query(
            Name::from_ascii("a.example.").expect("valid name"),
            RecordType::A,
        ));
        message.add_query(Query::query(
            Name::from_ascii("b.example.").expect("valid name"),
            RecordType::A,
        ));
        let handler = handler(limits(), Vec::new());
        let request = request(message.to_vec().expect("message must encode"));
        assert_eq!(handler.decode(&request), Err(ResponseCode::FormErr));
    }

    #[test]
    fn update_operation_is_not_implemented() {
        let mut message = Message::query();
        message.metadata.op_code = OpCode::Update;
        message.add_query(Query::query(
            Name::from_ascii("example.com.").expect("valid name"),
            RecordType::A,
        ));
        let handler = handler(limits(), Vec::new());
        let request = request(message.to_vec().expect("message must encode"));
        assert_eq!(handler.decode(&request), Err(ResponseCode::NotImp));
    }

    #[test]
    fn response_message_is_not_implemented() {
        let mut message = Message::response(42, OpCode::Query);
        message.add_query(Query::query(
            Name::from_ascii("example.com.").expect("valid name"),
            RecordType::A,
        ));
        let handler = handler(limits(), Vec::new());
        let request = request(message.to_vec().expect("message must encode"));
        assert_eq!(handler.decode(&request), Err(ResponseCode::NotImp));
    }

    #[test]
    fn context_extracts_edns_and_client() {
        let client = ClientConfig {
            id: "phone".to_owned(),
            name: "Phone".to_owned(),
            networks: vec![IpNet::V4(Ipv4Net::from(Ipv4Addr::LOCALHOST))],
            allowlist: Vec::new(),
            denylist: Vec::new(),
        };
        let handler = handler(limits(), vec![client]);
        let mut message = Message::query();
        message.add_query(Query::query(
            Name::from_ascii("example.com.").expect("valid name"),
            RecordType::A,
        ));
        message.set_edns(Edns::new());
        let request = request(message.to_vec().expect("message must encode"));
        let decoded = handler.decode(&request).expect("valid query");
        let context = handler.context(&request, &decoded);
        assert_eq!(context.client.id.as_deref(), Some("phone"));
        assert!(context.edns);
        assert_eq!(context.transport, Transport::Udp);
    }

    #[test]
    fn query_preserves_original_request_bytes() {
        let handler = handler(limits(), Vec::new());
        let bytes = query_message();
        let request = request(bytes.clone());
        let message = handler.decode(&request).expect("valid query");
        let query = NanoRequestHandler::<StubResolver>::query(&request, &message);
        assert_eq!(query.bytes, bytes);
        assert_eq!(query.name, "example.com.");
        assert_eq!(query.id, message.metadata.id);
    }

    #[test]
    fn semaphore_permits_are_enforced() {
        let handler = handler(
            RequestLimits {
                max_packet_bytes: 4096,
                max_concurrent_queries: 1,
            },
            Vec::new(),
        );
        let permit = handler
            .permits
            .clone()
            .try_acquire_owned()
            .expect("first permit");
        assert!(handler.permits.clone().try_acquire_owned().is_err());
        drop(permit);
        assert!(handler.permits.clone().try_acquire_owned().is_ok());
    }

    #[test]
    fn limits_follow_configuration() {
        let mut config = Listeners::default();
        config.max_packet_bytes = 4096;
        config.max_concurrent_queries = 8;
        let limits = RequestLimits::from_config(&config);
        assert_eq!(limits.max_packet_bytes, 4096);
        assert_eq!(limits.max_concurrent_queries, 8);
    }
}
