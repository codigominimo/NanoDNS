//! Shared interfaces between NanoDNS crates.
//!
//! These traits deliberately avoid Hickory types so that external protocol
//! details stay encapsulated in the crates that own them.

use std::future::Future;

use crate::error::Result;
use crate::model::{Decision, QueryContext, QueryEvent, Response, StatsSnapshot};

/// Resolves a query into a DNS response.
pub trait Resolver: Send + Sync {
    /// Opaque, protocol-specific query representation.
    type Query: Send;
    /// Future returned by [`Resolver::resolve`].
    type Future<'a>: Future<Output = Result<Response>> + Send
    where
        Self: 'a;

    /// Resolve `query` in the given request context.
    fn resolve(&self, query: Self::Query, context: &QueryContext) -> Self::Future<'_>;
}

/// Evaluates filtering policies for a query.
pub trait Policy: Send + Sync {
    /// Opaque, protocol-specific query representation.
    type Query;

    /// Return the policy decision for `query`.
    fn decide(&self, query: &Self::Query, context: &QueryContext) -> Decision;
}

/// Stores and retrieves DNS responses.
pub trait DnsCache: Send + Sync {
    /// Opaque, protocol-specific query representation.
    type Query;
    /// Look up a cached response.
    fn get(&self, query: &Self::Query, context: &QueryContext) -> Option<Response>;
    /// Insert a response into the cache.
    fn put(&self, query: &Self::Query, context: &QueryContext, response: &Response);
}

/// Optional persistence sink. Implementations must never block DNS queries.
pub trait Storage: Send + Sync {
    /// Queue one completed query for persistence.
    fn record(&self, event: QueryEvent) -> Result<()>;
    /// Flush queued events to durable storage.
    ///
    /// This is intended for shutdown or maintenance, not for the request path.
    fn flush(&self) -> Result<()>;
}

/// Optional statistics sink.
pub trait StatsSink: Send + Sync {
    /// Record one completed query.
    fn record(&self, event: &QueryEvent);

    /// Return counters for queries recorded in the configured retention window.
    fn snapshot(&self) -> StatsSnapshot;
}
