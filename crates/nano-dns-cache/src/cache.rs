//! In-memory DNS response cache with LRU eviction and TTL aging.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use hickory_proto::ProtoError;
use hickory_proto::op::Message;
use nano_dns_core::config::DnsCacheConfig;
use nano_dns_core::model::{DnsQuery, QueryContext, Response};
use nano_dns_core::traits::DnsCache;
use tracing::debug;

/// Injectable time source, used to make TTL tests deterministic.
pub type Clock = Arc<dyn Fn() -> Instant + Send + Sync>;

/// Cache key. The transaction id and other per-request flags are deliberately
/// excluded so that equivalent questions share an entry.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    name: String,
    query_type: u16,
    query_class: u16,
    dnssec_ok: bool,
}

impl CacheKey {
    fn new(query: &DnsQuery, context: &QueryContext) -> Self {
        Self {
            name: query.name.clone(),
            query_type: query.query_type,
            query_class: query.query_class,
            dnssec_ok: context.dnssec_ok,
        }
    }
}

/// One cached response.
#[derive(Debug, Clone)]
struct CacheEntry {
    response: Response,
    /// Effective TTL at insertion time.
    ttl: u32,
    negative: bool,
    inserted_at: Instant,
    last_used: u64,
    /// Memory contribution used for the soft byte limit.
    bytes: usize,
}

#[derive(Debug, Default)]
struct CacheState {
    entries: HashMap<CacheKey, CacheEntry>,
    total_bytes: usize,
    next_tick: u64,
}

/// Thread-safe bounded cache of DNS responses.
///
/// Entries are shared across clients, but DNSSEC and non-DNSSEC answers are
/// kept separate. TTLs stored in the encoded message are capped on insertion
/// and reduced on lookup so clients never receive a stale TTL.
pub struct MemoryCache {
    config: DnsCacheConfig,
    clock: Clock,
    state: Mutex<CacheState>,
}

impl MemoryCache {
    /// Create a cache using the system clock.
    pub fn new(config: &DnsCacheConfig) -> Self {
        Self::with_clock(config, Arc::new(Instant::now))
    }

    /// Create a cache with a custom clock.
    pub fn with_clock(config: &DnsCacheConfig, clock: Clock) -> Self {
        Self {
            config: config.clone(),
            clock,
            state: Mutex::new(CacheState::default()),
        }
    }

    /// Number of entries currently held. Useful for tests and diagnostics.
    pub fn len(&self) -> usize {
        self.lock().entries.len()
    }

    /// Whether the cache holds no entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, CacheState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Remove the least recently used entry until both limits are satisfied.
    fn evict(&self, state: &mut CacheState) {
        while state.entries.len() > self.config.max_entries
            || state.total_bytes > self.config.max_bytes
        {
            let victim = state
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_used)
                .map(|(key, _)| key.clone());
            match victim {
                Some(key) => {
                    if let Some(entry) = state.entries.remove(&key) {
                        state.total_bytes = state.total_bytes.saturating_sub(entry.bytes);
                    }
                }
                None => break,
            }
        }
    }
}

impl DnsCache for MemoryCache {
    type Query = DnsQuery;

    fn get(&self, query: &DnsQuery, context: &QueryContext) -> Option<Response> {
        let key = CacheKey::new(query, context);
        let now = (self.clock)();
        let mut state = self.lock();

        let expired = state.entries.get(&key).is_some_and(|entry| {
            now.saturating_duration_since(entry.inserted_at).as_secs() >= u64::from(entry.ttl)
        });
        if expired {
            if let Some(entry) = state.entries.remove(&key) {
                state.total_bytes = state.total_bytes.saturating_sub(entry.bytes);
            }
            return None;
        }

        state.next_tick += 1;
        let tick = state.next_tick;

        let aged = {
            let entry = state.entries.get_mut(&key)?;
            entry.last_used = tick;
            let age = u32::try_from(now.saturating_duration_since(entry.inserted_at).as_secs())
                .unwrap_or(u32::MAX)
                .min(entry.ttl);
            let result = rewrite_ttls(&entry.response.bytes, |ttl| ttl.saturating_sub(age));
            result.map(|(bytes, _)| (bytes, entry.ttl.saturating_sub(age), entry.negative))
        };

        match aged {
            Ok((bytes, ttl_secs, negative)) => Some(Response {
                bytes,
                ttl_secs,
                negative,
                cache_hit: true,
            }),
            Err(error) => {
                debug!(%error, "discarding invalid cached response");
                if let Some(entry) = state.entries.remove(&key) {
                    state.total_bytes = state.total_bytes.saturating_sub(entry.bytes);
                }
                None
            }
        }
    }

    fn put(&self, query: &DnsQuery, context: &QueryContext, response: &Response) {
        let cap = if response.negative {
            self.config.negative_ttl_secs
        } else {
            self.config.max_ttl_secs
        };
        let (bytes, min_ttl) = match rewrite_ttls(&response.bytes, |ttl| ttl.min(cap)) {
            Ok(result) => result,
            Err(error) => {
                debug!(%error, "not caching invalid DNS response");
                return;
            }
        };
        let ttl = if response.negative {
            self.config.negative_ttl_secs
        } else {
            min_ttl
        };
        if ttl == 0 {
            return;
        }

        let key = CacheKey::new(query, context);
        let bytes_len = bytes.len();
        let mut state = self.lock();
        state.next_tick += 1;
        let tick = state.next_tick;

        if let Some(old) = state.entries.remove(&key) {
            state.total_bytes = state.total_bytes.saturating_sub(old.bytes);
        }
        state.entries.insert(
            key,
            CacheEntry {
                response: Response {
                    bytes,
                    ttl_secs: ttl,
                    negative: response.negative,
                    cache_hit: false,
                },
                ttl,
                negative: response.negative,
                inserted_at: (self.clock)(),
                last_used: tick,
                bytes: bytes_len,
            },
        );
        state.total_bytes = state.total_bytes.saturating_add(bytes_len);
        self.evict(&mut state);
    }
}

/// Apply a transformation to every TTL in an encoded DNS message and return
/// the smallest resulting TTL. `0` means the message had no resource records.
fn rewrite_ttls(
    bytes: &[u8],
    transform: impl Fn(u32) -> u32,
) -> Result<(Vec<u8>, u32), ProtoError> {
    let mut message = Message::from_vec(bytes)?;
    let mut smallest = u32::MAX;
    for record in message
        .answers
        .iter_mut()
        .chain(message.authorities.iter_mut())
        .chain(message.additionals.iter_mut())
    {
        record.ttl = transform(record.ttl);
        smallest = smallest.min(record.ttl);
    }
    let bytes = message.to_vec()?;
    let smallest = if smallest == u32::MAX { 0 } else { smallest };
    Ok((bytes, smallest))
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    use hickory_proto::op::{Message, OpCode, ResponseCode};
    use hickory_proto::rr::{Name, RData, Record, RecordType, rdata::A};
    use nano_dns_core::model::{ClientIdentity, Transport};

    use super::*;

    struct TestClock {
        now: Arc<Mutex<Instant>>,
    }

    impl TestClock {
        fn new() -> (Self, Clock) {
            let now = Arc::new(Mutex::new(Instant::now()));
            let shared = Arc::clone(&now);
            let clock: Clock = Arc::new(move || {
                *shared
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
            });
            (Self { now }, clock)
        }

        fn advance(&self, seconds: u64) {
            let mut now = self
                .now
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            *now += Duration::from_secs(seconds);
        }
    }

    fn config() -> DnsCacheConfig {
        DnsCacheConfig {
            enabled: true,
            max_entries: 4,
            max_bytes: 1 << 20,
            max_ttl_secs: 300,
            negative_ttl_secs: 30,
        }
    }

    fn query(name: &str, qtype: RecordType) -> DnsQuery {
        DnsQuery {
            id: 1,
            name: name.to_owned(),
            query_type: u16::from(qtype),
            query_class: 1,
            bytes: Vec::new(),
        }
    }

    fn context(dnssec_ok: bool) -> QueryContext {
        QueryContext {
            client: ClientIdentity::new(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            transport: Transport::Udp,
            edns: false,
            udp_payload_size: None,
            dnssec_ok,
        }
    }

    fn response(name: &str, ttl: u32, negative: bool) -> Response {
        let mut message = Message::response(1, OpCode::Query);
        if negative {
            message.metadata.response_code = ResponseCode::NXDomain;
        } else {
            message.add_answer(Record::from_rdata(
                Name::from_ascii(name).expect("valid name"),
                ttl,
                RData::A(A::new(127, 0, 0, 1)),
            ));
        }
        Response {
            bytes: message.to_vec().expect("message must encode"),
            ttl_secs: ttl,
            negative,
            cache_hit: false,
        }
    }

    fn cached_ttl(bytes: &[u8]) -> u32 {
        let message = Message::from_vec(bytes).expect("cached message must decode");
        message.answers.first().map_or(0, |record| record.ttl)
    }

    #[test]
    fn stores_and_serves_identical_questions() {
        let cache = MemoryCache::new(&config());
        let query = query("example.com.", RecordType::A);
        let context = context(false);
        assert!(cache.get(&query, &context).is_none());

        cache.put(&query, &context, &response("example.com.", 120, false));
        let hit = cache.get(&query, &context).expect("cached response");
        assert_eq!(cached_ttl(&hit.bytes), 120);
        assert_eq!(hit.ttl_secs, 120);
    }

    #[test]
    fn query_type_and_dnssec_flag_are_part_of_the_key() {
        let cache = MemoryCache::new(&config());
        let base = query("example.com.", RecordType::A);
        let plain = context(false);
        cache.put(&base, &plain, &response("example.com.", 120, false));

        let other_type = query("example.com.", RecordType::AAAA);
        assert!(cache.get(&other_type, &plain).is_none());

        let dnssec = context(true);
        assert!(cache.get(&base, &dnssec).is_none());
    }

    #[test]
    fn ttl_is_aged_on_lookup_and_expires() {
        let (clock_handle, clock) = TestClock::new();
        let cache = MemoryCache::with_clock(&config(), clock);
        let query = query("example.com.", RecordType::A);
        let context = context(false);
        cache.put(&query, &context, &response("example.com.", 10, false));

        clock_handle.advance(4);
        let hit = cache.get(&query, &context).expect("response still valid");
        assert_eq!(cached_ttl(&hit.bytes), 6);
        assert_eq!(hit.ttl_secs, 6);

        clock_handle.advance(6);
        assert!(cache.get(&query, &context).is_none());
        assert!(cache.is_empty());
    }

    #[test]
    fn ttl_is_capped_on_insertion() {
        let cache = MemoryCache::new(&config());
        let query = query("example.com.", RecordType::A);
        let context = context(false);
        cache.put(&query, &context, &response("example.com.", 3600, false));

        let hit = cache.get(&query, &context).expect("cached response");
        assert_eq!(cached_ttl(&hit.bytes), 300);
        assert_eq!(hit.ttl_secs, 300);
    }

    #[test]
    fn negative_responses_use_the_negative_ttl() {
        let cache = MemoryCache::new(&config());
        let query = query("missing.example.", RecordType::A);
        let context = context(false);
        cache.put(&query, &context, &response("missing.example.", 0, true));

        let hit = cache.get(&query, &context).expect("negative entry");
        assert!(hit.negative);
        assert_eq!(hit.ttl_secs, 30);
    }

    #[test]
    fn least_recently_used_entry_is_evicted() {
        let mut config = config();
        config.max_entries = 2;
        let cache = MemoryCache::new(&config);
        let context = context(false);
        let first = query("a.example.", RecordType::A);
        let second = query("b.example.", RecordType::A);
        let third = query("c.example.", RecordType::A);

        cache.put(&first, &context, &response("a.example.", 60, false));
        cache.put(&second, &context, &response("b.example.", 60, false));
        let _ = cache.get(&first, &context);
        cache.put(&third, &context, &response("c.example.", 60, false));

        assert_eq!(cache.len(), 2);
        assert!(cache.get(&first, &context).is_some());
        assert!(cache.get(&second, &context).is_none());
        assert!(cache.get(&third, &context).is_some());
    }

    #[test]
    fn byte_limit_is_enforced() {
        let mut config = config();
        config.max_entries = 10;
        config.max_bytes = 1;
        let cache = MemoryCache::new(&config);
        let context = context(false);
        let query = query("example.com.", RecordType::A);
        cache.put(&query, &context, &response("example.com.", 60, false));
        assert!(cache.is_empty());
    }

    #[test]
    fn zero_ttl_responses_are_not_cached() {
        let cache = MemoryCache::new(&config());
        let query = query("example.com.", RecordType::A);
        let context = context(false);
        cache.put(&query, &context, &response("example.com.", 0, false));
        assert!(cache.get(&query, &context).is_none());
    }

    #[test]
    fn malformed_responses_are_not_cached() {
        let cache = MemoryCache::new(&config());
        let query = query("example.com.", RecordType::A);
        let context = context(false);
        cache.put(
            &query,
            &context,
            &Response {
                bytes: vec![0, 1, 2],
                ttl_secs: 60,
                negative: false,
                cache_hit: false,
            },
        );
        assert!(cache.get(&query, &context).is_none());
    }
}
