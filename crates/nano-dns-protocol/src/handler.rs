//! Request parsing, validation and response dispatch.
//!
//! Phase 2 accepted and validated DNS messages and answered `NOTIMP`.
//! Phase 3 forwards valid queries to the configured resolver pipeline.
//! Phase 5 evaluates a policy before resolving and builds blocked responses.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use hickory_proto::op::{
    Header, HeaderCounts, Message, MessageType, Metadata, OpCode, ResponseCode,
};
use hickory_proto::rr::{RData, Record, RecordType, rdata::A, rdata::AAAA};
use hickory_server::net::runtime::Time;
use hickory_server::net::xfer::Protocol;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::MessageResponseBuilder;
use nano_dns_core::config::{BlockResponse, BlockerConfig, ClientConfig, Listeners};
use nano_dns_core::model::{
    ClientIdentity, Decision, DnsQuery, QueryContext, QueryEvent, Response as CoreResponse,
    Transport,
};
use nano_dns_core::traits::{Policy, Resolver, StatsSink, Storage};
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

/// Response returned to clients whose query was blocked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockSettings {
    /// Blocking response mode.
    pub response: BlockResponse,
    /// Address returned for `A` queries in sinkhole mode.
    pub sinkhole_v4: Ipv4Addr,
    /// Address returned for `AAAA` queries in sinkhole mode.
    pub sinkhole_v6: Ipv6Addr,
}

impl Default for BlockSettings {
    fn default() -> Self {
        Self {
            response: BlockResponse::default(),
            sinkhole_v4: Ipv4Addr::UNSPECIFIED,
            sinkhole_v6: Ipv6Addr::UNSPECIFIED,
        }
    }
}

impl BlockSettings {
    /// Build block response settings from the blocker configuration.
    pub fn from_config(config: &BlockerConfig) -> Self {
        Self {
            response: config.block_response,
            sinkhole_v4: config.sinkhole_v4,
            sinkhole_v6: config.sinkhole_v6,
        }
    }
}

/// Handler installed in the Hickory DNS server.
pub struct NanoRequestHandler<R>
where
    R: Resolver<Query = DnsQuery>,
{
    resolver: Arc<R>,
    policy: Option<Arc<dyn Policy<Query = DnsQuery>>>,
    block: BlockSettings,
    limits: Arc<RequestLimits>,
    clients: Arc<Vec<ClientConfig>>,
    permits: Arc<Semaphore>,
    storage: Option<Arc<dyn Storage>>,
    stats: Option<Arc<dyn StatsSink>>,
}

impl<R> Clone for NanoRequestHandler<R>
where
    R: Resolver<Query = DnsQuery>,
{
    fn clone(&self) -> Self {
        Self {
            resolver: Arc::clone(&self.resolver),
            policy: self.policy.clone(),
            block: self.block,
            limits: Arc::clone(&self.limits),
            clients: Arc::clone(&self.clients),
            permits: Arc::clone(&self.permits),
            storage: self.storage.clone(),
            stats: self.stats.clone(),
        }
    }
}

impl<R> NanoRequestHandler<R>
where
    R: Resolver<Query = DnsQuery>,
{
    /// Create a handler with the given limits, client rules, resolver and
    /// optional policy.
    pub fn new(
        limits: RequestLimits,
        clients: Vec<ClientConfig>,
        resolver: R,
        policy: Option<Arc<dyn Policy<Query = DnsQuery>>>,
        block: BlockSettings,
    ) -> Self {
        Self::with_sinks(limits, clients, resolver, policy, block, None, None)
    }

    /// Create a handler with optional persistence and statistics sinks.
    pub fn with_sinks(
        limits: RequestLimits,
        clients: Vec<ClientConfig>,
        resolver: R,
        policy: Option<Arc<dyn Policy<Query = DnsQuery>>>,
        block: BlockSettings,
        storage: Option<Arc<dyn Storage>>,
        stats: Option<Arc<dyn StatsSink>>,
    ) -> Self {
        let permits = Arc::new(Semaphore::new(limits.max_concurrent_queries.max(1)));
        Self {
            resolver: Arc::new(resolver),
            policy,
            block,
            limits: Arc::new(limits),
            clients: Arc::new(clients),
            permits,
            storage,
            stats,
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

    /// Send a Hickory message while preserving the client transaction id.
    async fn send_message<S: ResponseHandler>(
        &self,
        request: &Request,
        message: Message,
        mut handle: S,
    ) -> ResponseInfo {
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

    /// Send a resolved response while preserving the client transaction id.
    async fn send_resolved<S: ResponseHandler>(
        &self,
        request: &Request,
        core_response: CoreResponse,
        handle: S,
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
        self.send_message(request, message, handle).await
    }

    /// Build the configured response for a blocked query.
    fn blocked_message(&self, request: &Request) -> Message {
        let mut response = Message::response(request.metadata.id, OpCode::Query);
        response.metadata = Metadata::response_from_request(&request.metadata);
        let question = request
            .queries
            .queries()
            .first()
            .map(|query| query.original().clone());
        if let Some(question) = &question {
            response.add_query(question.clone());
        }

        match self.block.response {
            BlockResponse::Nxdomain => {
                response.metadata.response_code = ResponseCode::NXDomain;
            }
            BlockResponse::Nodata => {
                response.metadata.response_code = ResponseCode::NoError;
            }
            BlockResponse::Sinkhole => {
                response.metadata.response_code = ResponseCode::NoError;
                if let Some(question) = question {
                    match question.query_type() {
                        RecordType::A => {
                            response.add_answer(Record::from_rdata(
                                question.name().clone(),
                                60,
                                RData::A(A::from(self.block.sinkhole_v4)),
                            ));
                        }
                        RecordType::AAAA => {
                            response.add_answer(Record::from_rdata(
                                question.name().clone(),
                                60,
                                RData::AAAA(AAAA::from(self.block.sinkhole_v6)),
                            ));
                        }
                        _ => {}
                    }
                }
            }
        }
        response
    }

    /// Send the configured blocked response without contacting the resolver.
    async fn send_blocked<S: ResponseHandler>(&self, request: &Request, handle: S) -> ResponseInfo {
        let message = self.blocked_message(request);
        self.send_message(request, message, handle).await
    }

    /// Current time in milliseconds since the Unix epoch.
    fn timestamp_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|duration| u64::try_from(duration.as_millis()).ok())
            .unwrap_or_default()
    }

    /// Extract the response code from an encoded DNS message.
    fn response_code(bytes: &[u8]) -> u16 {
        Message::from_vec(bytes)
            .map(|message| u16::from(message.metadata.response_code))
            .unwrap_or(u16::from(ResponseCode::ServFail))
    }

    /// Response metadata produced by the configured block mode.
    fn block_outcome(&self) -> (u16, u32, bool) {
        match self.block.response {
            BlockResponse::Nxdomain => (u16::from(ResponseCode::NXDomain), 0, true),
            BlockResponse::Nodata => (u16::from(ResponseCode::NoError), 0, true),
            BlockResponse::Sinkhole => (u16::from(ResponseCode::NoError), 60, false),
        }
    }

    /// Build a protocol-neutral event for optional persistence.
    fn query_event(
        timestamp_ms: u64,
        query: &DnsQuery,
        context: &QueryContext,
        decision: Decision,
        response_code: u16,
        ttl_secs: u32,
        negative: bool,
        cache_hit: bool,
    ) -> QueryEvent {
        QueryEvent {
            timestamp_ms,
            client_id: context.client.id.clone(),
            client_address: context.client.address,
            transport: context.transport,
            name: query.name.clone(),
            query_type: query.query_type,
            query_class: query.query_class,
            decision,
            response_code,
            ttl_secs,
            negative,
            cache_hit,
        }
    }

    /// Feed an event to optional sinks without ever failing the DNS query.
    fn record(&self, event: QueryEvent) {
        if let Some(storage) = &self.storage
            && let Err(error) = storage.record(event.clone())
        {
            warn!(%error, "cannot persist query event");
        }
        if let Some(stats) = &self.stats {
            stats.record(&event);
        }
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

        let timestamp_ms = Self::timestamp_ms();
        let context = self.context(request, &message);
        trace!(
            name = %message.queries[0].name(),
            qtype = %message.queries[0].query_type(),
            client_id = ?context.client.id,
            transport = ?context.transport,
            "DNS query accepted"
        );

        let query = Self::query(request, &message);
        if self
            .policy
            .as_ref()
            .is_some_and(|policy| policy.decide(&query, &context) == Decision::Block)
        {
            debug!(name = %query.name, "query blocked by policy");
            let (code, ttl_secs, negative) = self.block_outcome();
            self.record(Self::query_event(
                timestamp_ms,
                &query,
                &context,
                Decision::Block,
                code,
                ttl_secs,
                negative,
                false,
            ));
            return self.send_blocked(request, response_handle).await;
        }

        let event_query = query.clone();
        let event_context = context.clone();
        let result = self.resolver.resolve(query, &context).await;
        let outcome = match result {
            Ok(response) => {
                let code = Self::response_code(&response.bytes);
                self.record(Self::query_event(
                    timestamp_ms,
                    &event_query,
                    &event_context,
                    Decision::Allow,
                    code,
                    response.ttl_secs,
                    response.negative,
                    response.cache_hit,
                ));
                self.send_resolved(request, response, response_handle).await
            }
            Err(error) => {
                warn!(%error, "resolution failed");
                self.record(Self::query_event(
                    timestamp_ms,
                    &event_query,
                    &event_context,
                    Decision::Allow,
                    u16::from(ResponseCode::ServFail),
                    0,
                    false,
                    false,
                ));
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
    use std::sync::Mutex;

    use hickory_proto::op::{Edns, Query};
    use hickory_proto::rr::{Name, RecordType};
    use ipnet::{IpNet, Ipv4Net};
    use nano_dns_core::config::Listeners;
    use nano_dns_core::error::Result as CoreResult;
    use nano_dns_core::model::StatsSnapshot;

    #[derive(Clone, Default)]
    struct StubStorage {
        events: Arc<Mutex<Vec<QueryEvent>>>,
    }

    impl Storage for StubStorage {
        fn record(&self, event: QueryEvent) -> CoreResult<()> {
            self.events.lock().expect("test storage lock").push(event);
            Ok(())
        }

        fn flush(&self) -> CoreResult<()> {
            Ok(())
        }
    }

    #[derive(Clone, Default)]
    struct StubStats {
        events: Arc<Mutex<Vec<QueryEvent>>>,
    }

    impl StatsSink for StubStats {
        fn record(&self, event: &QueryEvent) {
            self.events
                .lock()
                .expect("test stats lock")
                .push(event.clone());
        }

        fn snapshot(&self) -> StatsSnapshot {
            StatsSnapshot {
                total_queries: self.events.lock().expect("test stats lock").len() as u64,
                ..StatsSnapshot::default()
            }
        }
    }

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
                    cache_hit: false,
                })
            })
        }
    }

    fn handler(
        limits: RequestLimits,
        clients: Vec<ClientConfig>,
    ) -> NanoRequestHandler<StubResolver> {
        NanoRequestHandler::new(
            limits,
            clients,
            StubResolver,
            None,
            BlockSettings::default(),
        )
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

    #[test]
    fn storage_receives_query_events() {
        let storage = Arc::new(StubStorage::default());
        let handler = NanoRequestHandler::with_sinks(
            limits(),
            Vec::new(),
            StubResolver,
            None,
            BlockSettings::default(),
            Some(storage.clone()),
            None,
        );
        let query = DnsQuery {
            id: 9,
            name: "example.com.".to_owned(),
            query_type: 1,
            query_class: 1,
            bytes: Vec::new(),
        };
        let context = QueryContext::new(
            ClientIdentity::new(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            Transport::Udp,
        );

        handler.record(NanoRequestHandler::<StubResolver>::query_event(
            42,
            &query,
            &context,
            Decision::Allow,
            0,
            60,
            false,
            false,
        ));

        let events = storage.events.lock().expect("test storage lock");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].timestamp_ms, 42);
        assert_eq!(events[0].name, "example.com.");
        assert_eq!(events[0].decision, Decision::Allow);
    }

    #[test]
    fn stats_receives_query_events() {
        let stats = Arc::new(StubStats::default());
        let handler = NanoRequestHandler::with_sinks(
            limits(),
            Vec::new(),
            StubResolver,
            None,
            BlockSettings::default(),
            None,
            Some(stats.clone()),
        );
        let query = DnsQuery {
            id: 9,
            name: "example.com.".to_owned(),
            query_type: 1,
            query_class: 1,
            bytes: Vec::new(),
        };
        let context = QueryContext::new(
            ClientIdentity::new(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            Transport::Udp,
        );

        handler.record(NanoRequestHandler::<StubResolver>::query_event(
            42,
            &query,
            &context,
            Decision::Allow,
            0,
            60,
            false,
            true,
        ));

        assert_eq!(stats.snapshot().total_queries, 1);
        let events = stats.events.lock().expect("test stats lock");
        assert_eq!(events.len(), 1);
        assert!(events[0].cache_hit);
    }
}
