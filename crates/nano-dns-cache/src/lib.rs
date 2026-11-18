//! In-memory DNS response cache for NanoDNS.
//!
//! The cache is protocol-neutral from the core's point of view: it implements
//! the `DnsCache` trait with `DnsQuery` keys and `Response` values. Hickory is
//! used only to age the TTLs embedded in the encoded DNS message.

pub mod cache;
pub mod resolver;

pub use cache::{Clock, MemoryCache};
pub use resolver::CachingResolver;
