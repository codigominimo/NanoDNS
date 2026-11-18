//! Resolver decorator that serves cache hits and fills misses from an inner resolver.

use std::future::Future;
use std::pin::Pin;

use nano_dns_core::error::Result;
use nano_dns_core::model::{DnsQuery, QueryContext, Response};
use nano_dns_core::traits::{DnsCache, Resolver};

/// Adds a cache in front of any [`Resolver`].
///
/// When no cache is configured the wrapper is a transparent pass-through, so
/// the server keeps a single concrete type whether or not caching is enabled.
pub struct CachingResolver<R, C> {
    inner: R,
    cache: Option<C>,
}

impl<R, C> CachingResolver<R, C>
where
    R: Resolver<Query = DnsQuery>,
    C: DnsCache<Query = DnsQuery>,
{
    /// Wrap `inner` with an active cache.
    pub fn new(inner: R, cache: C) -> Self {
        Self {
            inner,
            cache: Some(cache),
        }
    }

    /// Wrap `inner` without caching.
    pub fn passthrough(inner: R) -> Self {
        Self { inner, cache: None }
    }
}

impl<R, C> Resolver for CachingResolver<R, C>
where
    R: Resolver<Query = DnsQuery> + 'static,
    C: DnsCache<Query = DnsQuery> + 'static,
{
    type Query = DnsQuery;
    type Future<'a>
        = Pin<Box<dyn Future<Output = Result<Response>> + Send + 'a>>
    where
        Self: 'a;

    fn resolve(&self, query: DnsQuery, context: &QueryContext) -> Self::Future<'_> {
        let context = context.clone();
        Box::pin(async move {
            if let Some(cache) = self.cache.as_ref() {
                if let Some(hit) = cache.get(&query, &context) {
                    return Ok(hit);
                }
            }

            let response = self.inner.resolve(query.clone(), &context).await?;
            if let Some(cache) = self.cache.as_ref() {
                cache.put(&query, &context, &response);
            }
            Ok(response)
        })
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::net::{IpAddr, Ipv4Addr};
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use nano_dns_core::config::DnsCacheConfig;
    use nano_dns_core::model::{ClientIdentity, Transport};

    use super::*;
    use crate::cache::MemoryCache;

    struct CountingResolver {
        calls: Arc<AtomicUsize>,
    }

    impl Resolver for CountingResolver {
        type Query = DnsQuery;
        type Future<'a>
            = Pin<Box<dyn Future<Output = Result<Response>> + Send + 'a>>
        where
            Self: 'a;

        fn resolve(&self, _query: DnsQuery, _context: &QueryContext) -> Self::Future<'_> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async {
                Ok(Response {
                    bytes: Vec::new(),
                    ttl_secs: 0,
                    negative: false,
                    cache_hit: false,
                })
            })
        }
    }

    fn query() -> DnsQuery {
        DnsQuery {
            id: 1,
            name: "example.com.".to_owned(),
            query_type: 1,
            query_class: 1,
            bytes: Vec::new(),
        }
    }

    fn context() -> QueryContext {
        QueryContext::new(
            ClientIdentity::new(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            Transport::Udp,
        )
    }

    #[tokio::test]
    async fn cache_hits_avoid_the_inner_resolver() {
        let calls = Arc::new(AtomicUsize::new(0));
        let inner = CountingResolver {
            calls: Arc::clone(&calls),
        };
        let mut config = DnsCacheConfig::default();
        config.max_ttl_secs = 60;
        let cache = MemoryCache::new(&config);
        let resolver = CachingResolver::new(inner, cache);
        let context = context();

        // An empty byte payload cannot be cached, so use a valid encoded
        // message instead by injecting it through the cache directly.
        let mut message = hickory_proto::op::Message::response(1, hickory_proto::op::OpCode::Query);
        message.add_answer(hickory_proto::rr::Record::from_rdata(
            hickory_proto::rr::Name::from_ascii("example.com.").expect("valid name"),
            60,
            hickory_proto::rr::RData::A(hickory_proto::rr::rdata::A::new(127, 0, 0, 1)),
        ));
        let bytes = message.to_vec().expect("message must encode");
        resolver.cache.as_ref().expect("cache").put(
            &query(),
            &context,
            &Response {
                bytes,
                ttl_secs: 60,
                negative: false,
                cache_hit: false,
            },
        );

        let _ = resolver.resolve(query(), &context).await.expect("resolve");
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn cache_misses_call_the_inner_resolver() {
        let calls = Arc::new(AtomicUsize::new(0));
        let inner = CountingResolver {
            calls: Arc::clone(&calls),
        };
        let resolver = CachingResolver::<_, MemoryCache>::passthrough(inner);
        let context = context();

        let _ = resolver.resolve(query(), &context).await.expect("resolve");
        let _ = resolver.resolve(query(), &context).await.expect("resolve");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }
}
