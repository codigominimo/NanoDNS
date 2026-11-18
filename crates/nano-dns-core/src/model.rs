//! Protocol-agnostic domain types shared by NanoDNS crates.
//!
//! Concrete DNS message types from Hickory stay inside `nano-dns-protocol`
//! and `nano-dns-resolver`. This module only contains the small vocabulary
//! needed to connect the pipeline stages.

use std::collections::BTreeMap;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

/// Identity of a client that sent a DNS query.
///
/// The address must come from the socket peer, never from DNS headers or
/// EDNS options supplied by the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientIdentity {
    /// Stable identifier assigned by configuration, if one matched.
    pub id: Option<String>,
    /// Observed peer address.
    pub address: IpAddr,
}

impl ClientIdentity {
    /// Create an unidentified client from a peer address.
    pub fn new(address: IpAddr) -> Self {
        Self { id: None, address }
    }
}

/// Transport used to receive a query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// Plain DNS over UDP.
    Udp,
    /// Plain DNS over TCP.
    Tcp,
    /// DNS over TLS.
    Dot,
    /// DNS over HTTPS.
    Doh,
}

/// Protocol-neutral view of one DNS question.
///
/// `bytes` is the original encoded request and is forwarded unchanged so that
/// flags and EDNS options are not silently rewritten between stages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuery {
    /// Transaction id from the original request.
    pub id: u16,
    /// Lower-cased queried name.
    pub name: String,
    /// Numeric DNS record type.
    pub query_type: u16,
    /// Numeric DNS class.
    pub query_class: u16,
    /// Original encoded request bytes.
    pub bytes: Vec<u8>,
}

/// Context associated with one query as it traverses the pipeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryContext {
    /// Client that sent the query.
    pub client: ClientIdentity,
    /// Transport used by the client.
    pub transport: Transport,
    /// Whether EDNS0 was present in the request.
    pub edns: bool,
    /// Requested maximum UDP payload size, when EDNS0 was present.
    pub udp_payload_size: Option<u16>,
    /// Whether the client requested DNSSEC validation.
    pub dnssec_ok: bool,
}

impl QueryContext {
    /// Create a minimal context for a client and transport.
    pub fn new(client: ClientIdentity, transport: Transport) -> Self {
        Self {
            client,
            transport,
            edns: false,
            udp_payload_size: None,
            dnssec_ok: false,
        }
    }
}

/// Outcome of a policy evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Resolve normally.
    Allow,
    /// Answer with the configured blocked response.
    Block,
}

/// One completed DNS query recorded by optional persistence.
///
/// This type is protocol-neutral: the numeric response code is extracted by
/// the transport layer, which owns the DNS message representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryEvent {
    /// Completion time as milliseconds since the Unix epoch.
    pub timestamp_ms: u64,
    /// Configured client identifier, when one matched.
    pub client_id: Option<String>,
    /// Observed peer address.
    pub client_address: IpAddr,
    /// Transport used by the client.
    pub transport: Transport,
    /// Lower-cased queried name.
    pub name: String,
    /// Numeric DNS record type.
    pub query_type: u16,
    /// Numeric DNS class.
    pub query_class: u16,
    /// Policy decision for this query.
    pub decision: Decision,
    /// Numeric DNS response code.
    pub response_code: u16,
    /// Remaining TTL returned to the client.
    pub ttl_secs: u32,
    /// Whether the response was negative.
    pub negative: bool,
    /// Whether the response was served from the DNS cache.
    pub cache_hit: bool,
}

/// Aggregated counters for a recent time window.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatsSnapshot {
    /// Number of queries in the window.
    pub total_queries: u64,
    /// Number of allowed queries.
    pub allowed: u64,
    /// Number of blocked queries.
    pub blocked: u64,
    /// Number of cache hits.
    pub cache_hits: u64,
    /// Number of SERVFAIL responses.
    pub errors: u64,
    /// Counters by numeric response code.
    pub response_codes: BTreeMap<u16, u64>,
    /// Counters by query type.
    pub query_types: BTreeMap<u16, u64>,
    /// Counters by transport name.
    pub transports: BTreeMap<String, u64>,
    /// Most queried domains, highest count first.
    pub top_domains: Vec<(String, u64)>,
    /// Number of domains kept in the top-domain table.
    pub top_domains_capacity: usize,
}

/// A resolved response ready to be encoded and returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// Opaque serialized DNS message. Encoding is owned by the protocol crate.
    pub bytes: Vec<u8>,
    /// Remaining TTL of the response, in seconds.
    pub ttl_secs: u32,
    /// Whether the response is a negative (NXDOMAIN/NODATA) answer.
    pub negative: bool,
    /// Whether the response was served from the DNS cache.
    pub cache_hit: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn context_uses_peer_address_for_identity() {
        let address = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20));
        let context = QueryContext::new(ClientIdentity::new(address), Transport::Udp);
        assert_eq!(context.client.address, address);
        assert!(!context.edns);
    }
}
